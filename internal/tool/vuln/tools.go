package vuln

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcp-server/internal/api"
	"mcp-server/internal/tool/helpers"
	"mcp-server/internal/tool/registry"
)

const vulnEventInputSchema = `{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"},"asset":{"type":"string","description":"Asset slug"},"assetVersion":{"type":"string","description":"Asset version slug (branch or tag ref, e.g. 'main')"},"vulnType":{"type":"string","enum":["dependency","first-party"],"description":"Type of vulnerability: 'dependency' for dependency vulnerabilities or 'first-party' for first-party vulnerabilities"},"vulnID":{"type":"string","description":"Vulnerability ID (UUID)"},"justification":{"type":"string","description":"Justification text for the status change. Supports Markdown formatting (headings, bullet lists, code blocks, bold/italic). Write a clear, structured explanation of the reasoning."}},"required":["organization","project","asset","assetVersion","vulnType","vulnID"]}`

func Register(r *registry.Registry, client api.Client) {
	r.Add(&mcp.Tool{
		Name: "list_dependency_vulns",
		Description: `List dependency vulnerabilities (SCA) for a specific asset version.

If the user confirms assessment, process open vulnerabilities grouped by severity — in this order: CRITICAL (CVSS ≥ 9.0), HIGH (7.0–8.9), MEDIUM (4.0–6.9), LOW (< 4.0).
Within each severity group, call get_vuln_details for each vulnerability and apply the assessment logic described there before moving to the next group.
This grouping ensures expensive reachability analysis is spent on the highest-risk issues first.`,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"},"asset":{"type":"string","description":"Asset slug"},"assetVersion":{"type":"string","description":"Asset version slug (branch or tag ref, e.g. 'main')"}},"required":["organization","project","asset","assetVersion"]}`),
	}, listDependencyVulns(client))

	r.Add(&mcp.Tool{
		Name:        "list_first_party_vulns",
		Description: `List first-party vulnerabilities for a specific asset version.`,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"},"asset":{"type":"string","description":"Asset slug"},"assetVersion":{"type":"string","description":"Asset version slug (branch or tag ref, e.g. 'main')"}},"required":["organization","project","asset","assetVersion"]}`),
	}, listFirstPartyVulns(client))

	r.Add(&mcp.Tool{
		Name: "get_vuln_details",
		Description: `Fetch full details of a single vulnerability including CVE description, CVSS, EPSS score, attack vector, exploit availability, dependency path, fix version, and event history.

ASSESSMENT LOGIC — apply this after fetching details:

1. FIX (highest priority):
   If directDependencyFixedVersion is set → always recommend fixing, regardless of reachability or severity.

2. FALSE POSITIVE — VERIFY THE PACKAGE IS A REAL PRODUCTION DEPENDENCY (always do this first):
   Parse the componentPurl to extract the package name and version (e.g. pkg:npm/lodash@4.17.21 → name: lodash, pkg:golang/github.com/foo/bar@v1.2.3 → module path: github.com/foo/bar).

   STEP A — Find the canonical dependency declaration:
   Search for where this package is declared as an actual dependency in the project's dependency manifest files:
   - JavaScript/TypeScript: package.json (dependencies, peerDependencies), package-lock.json, yarn.lock, pnpm-lock.yaml
   - Go: go.mod, go.sum
   - Python: requirements.txt, pyproject.toml, setup.py, Pipfile, poetry.lock
   - Java/Kotlin: pom.xml, build.gradle, gradle.lockfile
   - Rust: Cargo.toml, Cargo.lock
   - Ruby: Gemfile, Gemfile.lock
   - .NET: *.csproj, packages.lock.json

   STEP B — Determine the source context of those manifest files:
   Check whether the manifest files that declare this package are themselves inside a non-production directory:
   - testdata/, test-fixtures/, fixtures/, __fixtures__/, testfiles/, sample-data/, examples/, demo/
   - Any directory whose path contains: test, spec, mock, stub, fake, example, sample, demo
   - SBOM/CycloneDX/SPDX fixture files (*.cdx.json, *.sbom.json, *.spdx.json, large-sbom*.json, etc.) that serve as test input data for the scanner itself

   If the ONLY references to this package are inside such non-production directories or fixture files, the package is NOT part of the actual software being shipped → call mark_vuln_false_positive with justification: "package [name] only appears in [file path(s)], which are test fixture/sample data files, not a real installed dependency of the project".

   STEP C — Check production vs. dev scope within real manifests:
   If the package IS in a real manifest, check whether it is scoped exclusively to dev/test:
   - npm: only in devDependencies (never in dependencies or peerDependencies)
   - Maven: scope=test or scope=provided only
   - Gradle: testImplementation / testRuntimeOnly only
   - Python: only in [dev-dependencies] / extras = ["dev"] groups
   - Go: only imported in *_test.go files
   → If dev/test-only → call mark_vuln_false_positive with justification "package only declared as dev/test dependency, not part of production build".

   If the package is a legitimate production dependency → continue to step 3.

3. FALSE POSITIVE — REACHABILITY ANALYSIS:
   Only if you are certain the vulnerable code is NOT reachable in production.
   Perform reachability analysis in stages based on the vulnerabilityPath:

   STAGE A — Direct dependency:
   If vulnerabilityPath has only 1 hop (direct dependency):
   - Extract the specific vulnerable function/class/method from the CVE description.
   - Search the codebase using grep/ripgrep for: the exact function name, common call patterns, and any import of the package.
   - If the vulnerable function is definitively not called anywhere → call mark_vuln_false_positive.

   STAGE B — Transitive dependency (vulnerabilityPath has 2+ hops):
   The path looks like: [your-project → direct-dep → ... → vulnerable-pkg]
   Work through the chain step by step:
   Step 1: Identify the vulnerable function in vulnerable-pkg from the CVE description.
   Step 2: Search the intermediate dependency (the package one level above vulnerable-pkg in the path) for calls to that function. Look in vendor/, node_modules/, or the package source if available. Identify which function(s) in the intermediate package call the vulnerable function.
   Step 3: Search the project source code for calls to those intermediate functions (the ones found in Step 2).
   Step 4: If the project does not call any of those intermediate functions → the vulnerability is not reachable → call mark_vuln_false_positive with detailed justification of the full call-chain analysis.
   Step 5: If the project does call those functions, check WHICH project functions make those calls, and whether those project functions are themselves reachable (e.g. not dead code, not test-only). If they are unreachable/dead code → call mark_vuln_false_positive. If reachable → the vulnerability is reachable, proceed to step 4.

   For large transitive chains (3+ hops), repeat the pattern: find the callers at each level until you either confirm reachability or confirm it is not reachable.
   Use mark_vuln_false_positive sparingly: when in doubt or if the analysis is inconclusive, prefer accept_vuln.

4. ACCEPT:
   The vulnerability is real and potentially reachable, but risk is consciously accepted. Call accept_vuln when ALL of the following apply:
   - No fix available
   - Not clearly unreachable (otherwise mark_vuln_false_positive)
   - Multiple risk signals are low: EPSS < 0.01 AND no verified exploits, OR attack vector is LOCAL/PHYSICAL, OR CVSS < 4.0 with no known exploits

5. Otherwise → recommend the user to investigate and fix manually.

Always include a justification string explaining your reasoning when calling accept_vuln or mark_vuln_false_positive.
The justification MUST include: which files were searched, what was or was not found, and the full reasoning for the conclusion.`,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"},"asset":{"type":"string","description":"Asset slug"},"assetVersion":{"type":"string","description":"Asset version slug (branch or tag ref, e.g. 'main')"},"vulnType":{"type":"string","enum":["dependency","first-party"],"description":"Type of vulnerability"},"vulnID":{"type":"string","description":"Vulnerability ID (UUID)"}},"required":["organization","project","asset","assetVersion","vulnType","vulnID"]}`),
	}, getVulnDetails(client))

	r.Add(&mcp.Tool{
		Name:        "accept_vuln",
		Description: "Accept a vulnerability (risk consciously accepted). Use when no fix is available and multiple low-risk signals apply. Always pass a justification explaining why the risk is accepted.",
		InputSchema: json.RawMessage(vulnEventInputSchema),
	}, createVulnEvent(client, "accepted"))

	r.Add(&mcp.Tool{
		Name:        "mark_vuln_false_positive",
		Description: "Mark a vulnerability as false positive. Only use when you have confirmed through codebase analysis that the vulnerable function is definitively not reachable. Always pass a justification with the specific evidence (e.g. which function was searched and not found).",
		InputSchema: json.RawMessage(vulnEventInputSchema),
	}, createVulnEvent(client, "falsePositive"))
}

type vulnEventArgs struct {
	Organization  string `json:"organization"`
	Project       string `json:"project"`
	Asset         string `json:"asset"`
	AssetVersion  string `json:"assetVersion"`
	VulnType      string `json:"vulnType"`
	VulnID        string `json:"vulnID"`
	Justification string `json:"justification"`
}

func vulnBasePath(args vulnEventArgs) string {
	vulnSegment := "dependency-vulns"
	if args.VulnType == "first-party" {
		vulnSegment = "first-party-vulns"
	}
	return fmt.Sprintf("/organizations/%s/projects/%s/assets/%s/refs/%s/%s/%s",
		args.Organization, args.Project, args.Asset, args.AssetVersion, vulnSegment, args.VulnID)
}

func getVulnDetails(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
			Project      string `json:"project"`
			Asset        string `json:"asset"`
			AssetVersion string `json:"assetVersion"`
			VulnType     string `json:"vulnType"`
			VulnID       string `json:"vulnID"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		vulnSegment := "dependency-vulns"
		if args.VulnType == "first-party" {
			vulnSegment = "first-party-vulns"
		}
		path := fmt.Sprintf("/organizations/%s/projects/%s/assets/%s/refs/%s/%s/%s/",
			args.Organization, args.Project, args.Asset, args.AssetVersion, vulnSegment, args.VulnID)

		details, err := api.Get[api.DetailedDependencyVulnResponse](ctx, client, path)
		if err != nil {
			return helpers.Errorf("Error fetching vulnerability details: %v", err), nil
		}

		hintsPath := path + "hints/"
		hints, _ := api.Get[api.VulnHintResponse](ctx, client, hintsPath)

		return helpers.JSON(map[string]any{
			"vuln":      details,
			"hints":     hints,
			"next_step": "Based on the assessment above: should I apply the suggested actions (mark as false positive or accept the vulnerability)?",
		}), nil
	}
}

func createVulnEvent(client api.Client, status string) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args vulnEventArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		path := vulnBasePath(args) + "/"
		body := map[string]any{"status": status, "justification": args.Justification}
		_, err := client.Post(ctx, path, body)
		if err != nil {
			return helpers.Errorf("Error creating vuln event: %v", err), nil
		}
		return helpers.JSON(map[string]string{"status": status, "vulnID": args.VulnID}), nil
	}
}

func listDependencyVulns(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
			Project      string `json:"project"`
			Asset        string `json:"asset"`
			AssetVersion string `json:"assetVersion"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		path := fmt.Sprintf("/organizations/%s/projects/%s/assets/%s/refs/%s/dependency-vulns?flat=true&pageSize=100",
			args.Organization, args.Project, args.Asset, args.AssetVersion)
		paged, err := api.Get[api.PagedResponse[api.DependencyVulnResponse]](ctx, client, path)
		if err != nil {
			return helpers.Errorf("Error fetching dependency vulnerabilities: %v", err), nil
		}
		return helpers.JSON(map[string]any{
			"vulnerabilities": paged.Data,
			"next_step":       `Should I get details and analyze the vulnerabilities one by one? If yes, please provide the path to the source code (or a repository URL).`,
		}), nil
	}
}

func listFirstPartyVulns(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
			Project      string `json:"project"`
			Asset        string `json:"asset"`
			AssetVersion string `json:"assetVersion"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		path := fmt.Sprintf("/organizations/%s/projects/%s/assets/%s/refs/%s/first-party-vulns",
			args.Organization, args.Project, args.Asset, args.AssetVersion)
		paged, err := api.Get[api.PagedResponse[api.FirstPartyVulnResponse]](ctx, client, path)
		if err != nil {
			return helpers.Errorf("Error fetching first-party vulnerabilities: %v", err), nil
		}
		return helpers.JSON(map[string]any{
			"vulnerabilities": paged.Data,
		}), nil
	}
}
