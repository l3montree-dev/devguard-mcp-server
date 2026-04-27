package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcp-server/internal/api"
	"mcp-server/internal/config"
	"mcp-server/internal/tool/helpers"
	"mcp-server/internal/tool/registry"
)

var configPAT string
var configAPIURL string

func commonProps() string {
	return `
		"assetName":  {"type":"string","description":"Asset name in DevGuard: organizationSlug/projectSlug/assetSlug"},
		"token":      {"type":"string","description":"DevGuard personal access token (falls back to DEVGUARD_PAT env var)"},
		"apiUrl":     {"type":"string","description":"DevGuard API URL (falls back to DEVGUARD_API_URL env var)"},
		"ref":        {"type":"string","description":"Git reference (branch, tag, or commit hash)"},
		"defaultRef": {"type":"string","description":"Default git reference"},
		"isTag":      {"type":"boolean","description":"Whether the current ref is a tag"},
		"webUI":      {"type":"string","description":"DevGuard web UI URL"},
		"outputPath": {"type":"string","description":"Path to save the output report"},
		"timeout":    {"type":"integer","description":"Scanner timeout in seconds (default: 300)"}`
}

const (
	sbomProps = `
		"failOnRisk":                    {"type":"string","description":"Fail if risk >= level: low|medium|high|critical"},
		"failOnCVSS":                    {"type":"string","description":"Fail if CVSS >= level: low|medium|high|critical"},
		"artifactName":                  {"type":"string","description":"Name of the artifact being scanned"},
		"origin":                        {"type":"string","description":"SBOM origin (default: DEFAULT)"},
		"ignoreExternalReferences":      {"type":"boolean","description":"Ignore external SBOM/VEX references"},
		"keepOriginalSbomRootComponent": {"type":"boolean","description":"Also scan the root component itself for vulnerabilities"}`
)

func Register(r *registry.Registry, _ api.Client) {
	cfg, err := config.Load()
	if err == nil {
		configPAT = cfg.PAT
		configAPIURL = strings.TrimSuffix(cfg.APIBaseURL, "/api/v1")
	}

	r.Add(&mcp.Tool{
		Name:        "ensure_scanner_installed",
		Description: "Check if devguard-scanner is installed and install it if not",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	}, ensureScannerInstalled)

	r.Add(&mcp.Tool{
		Name:        "run_sca",
		Description: "Run Software Composition Analysis (dependency vulnerability scan) on a project directory or container image.\n\nAfter the scan completes successfully, ask the user whether they want to call get_vuln_details for each discovered vulnerability to get full details and apply assessment logic.",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,%s,"path":{"type":"string","description":"Path to project directory or tar file"}},"required":["assetName","path"]}`, commonProps(), sbomProps)),
	}, runSCA)

	r.Add(&mcp.Tool{
		Name:        "run_container_scanning",
		Description: "Run vulnerability scan on an OCI container image.\n\nAfter the scan completes successfully, ask the user whether they want to call get_vuln_details for each discovered vulnerability to get full details and apply assessment logic.",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,%s,"image":{"type":"string","description":"OCI image reference, e.g. ghcr.io/org/image:tag"},"path":{"type":"string","description":"Path to a tar file or directory"},"ignoreUpstreamAttestations":{"type":"boolean","description":"Ignore attestations from the scanned image"}},"required":["assetName","path"]}`, commonProps(), sbomProps)),
	}, runContainerScanning)

	r.Add(&mcp.Tool{
		Name:        "run_sast",
		Description: "Run Static Application Security Testing (SAST) on a project directory",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,"path":{"type":"string","description":"Path to project directory (default: .)"}},"required":["assetName"]}`, commonProps())),
	}, runSAST)

	r.Add(&mcp.Tool{
		Name:        "run_secret_scanning",
		Description: "Scan a project directory for leaked secrets and credentials",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,"path":{"type":"string","description":"Path to project directory (default: .)"}},"required":["assetName"]}`, commonProps())),
	}, runSecretScanning)

	r.Add(&mcp.Tool{
		Name:        "run_iac",
		Description: "Run Infrastructure-as-Code (IaC) security scan on a project directory",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,"path":{"type":"string","description":"Path to project directory (default: .)"}},"required":["assetName"]}`, commonProps())),
	}, runIAC)

	r.Add(&mcp.Tool{
		Name:        "run_sbom",
		Description: "Upload a CycloneDX or SPDX SBOM to DevGuard and check it for vulnerabilities",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,%s,"sbomFile":{"type":"string","description":"Path to SBOM JSON file (or '-' for stdin)"}},"required":["assetName","sbomFile"]}`, commonProps(), sbomProps)),
	}, runSBOM)

	r.Add(&mcp.Tool{
		Name:        "run_sarif",
		Description: "Upload a SARIF report to DevGuard",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,"sarifFile":{"type":"string","description":"Path to SARIF JSON file"},"scannerID":{"type":"string","description":"Scanner identifier URI"}},"required":["assetName","sarifFile"]}`, commonProps())),
	}, runSARIF)

	r.Add(&mcp.Tool{
		Name:        "run_vex",
		Description: "Upload a VEX (Vulnerability Exploitability eXchange) document to DevGuard",
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s,%s,"vexFile":{"type":"string","description":"Path to VEX file"}},"required":["assetName","vexFile"]}`, commonProps(), sbomProps)),
	}, runVEX)
}

func runScanner(ctx context.Context, subcommand string, flags map[string]string, positionalArgs ...string) *mcp.CallToolResult {
	args := []string{subcommand}
	for k, v := range flags {
		if v == "" {
			continue
		}
		args = append(args, "--"+k, v)
	}
	args = append(args, positionalArgs...)

	cmd := exec.CommandContext(ctx, "devguard-scanner", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return helpers.Errorf("devguard-scanner %s failed: %v\n%s", subcommand, err, out.String())
	}
	return helpers.Text(out.String())
}

func extractCommonFlags(m map[string]any) map[string]string {
	flags := map[string]string{}
	for _, k := range []string{"assetName", "token", "apiUrl", "ref", "defaultRef", "webUI", "outputPath", "artifactName"} {
		if v, ok := m[k].(string); ok && v != "" {
			flags[k] = v
		}
	}
	if flags["token"] == "" && configPAT != "" {
		flags["token"] = configPAT
	}
	if flags["apiUrl"] == "" && configAPIURL != "" {
		flags["apiUrl"] = configAPIURL
	}
	if v, ok := m["isTag"].(bool); ok && v {
		flags["isTag"] = "true"
	}
	if v, ok := m["timeout"].(float64); ok {
		flags["timeout"] = strconv.Itoa(int(v))
	}
	return flags
}

func extractSbomFlags(m map[string]any, flags map[string]string) {
	for _, k := range []string{"failOnRisk", "failOnCVSS", "origin"} {
		if v, ok := m[k].(string); ok && v != "" {
			flags[k] = v
		}
	}
	if v, ok := m["ignoreExternalReferences"].(bool); ok && v {
		flags["ignoreExternalReferences"] = "true"
	}
	if v, ok := m["keepOriginalSbomRootComponent"].(bool); ok && v {
		flags["keepOriginalSbomRootComponent"] = "true"
	}
}

func parseArgs(req *mcp.CallToolRequest) (map[string]any, error) {
	var m map[string]any
	return m, json.Unmarshal(req.Params.Arguments, &m)
}

func ensureScannerInstalled(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if _, err := exec.LookPath("devguard-scanner"); err == nil {
		return helpers.Text("devguard-scanner is already installed"), nil
	}
	if _, err := exec.LookPath("go"); err != nil {
		return helpers.Errorf("devguard-scanner is not installed and Go is not available. Please install Go first: https://go.dev/doc/install"), nil
	}
	out, err := exec.Command("go", "install", "github.com/l3montree-dev/devguard/cmd/devguard-scanner@latest").CombinedOutput()
	if err != nil {
		return helpers.Errorf("installation failed: %v\n%s", err, string(out)), nil
	}
	return helpers.Text(fmt.Sprintf("devguard-scanner installed successfully:\n%s", string(out))), nil
}

func runSCA(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	flags := extractCommonFlags(m)
	extractSbomFlags(m, flags)
	if v, ok := m["path"].(string); ok && v != "" {
		flags["path"] = v
	}
	return runScanner(ctx, "sca", flags), nil
}

func runContainerScanning(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	flags := extractCommonFlags(m)
	extractSbomFlags(m, flags)
	for _, k := range []string{"image", "path"} {
		if v, ok := m[k].(string); ok && v != "" {
			flags[k] = v
		}
	}
	if v, ok := m["ignoreUpstreamAttestations"].(bool); ok && v {
		flags["ignoreUpstreamAttestations"] = "true"
	}
	return runScanner(ctx, "container-scanning", flags), nil
}

func runSAST(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	flags := extractCommonFlags(m)
	if v, ok := m["path"].(string); ok && v != "" {
		flags["path"] = v
	}
	return runScanner(ctx, "sast", flags), nil
}

func runSecretScanning(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	flags := extractCommonFlags(m)
	if v, ok := m["path"].(string); ok && v != "" {
		flags["path"] = v
	}
	return runScanner(ctx, "secret-scanning", flags), nil
}

func runIAC(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	flags := extractCommonFlags(m)
	if v, ok := m["path"].(string); ok && v != "" {
		flags["path"] = v
	}
	return runScanner(ctx, "iac", flags), nil
}

func runSBOM(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	sbomFile, _ := m["sbomFile"].(string)
	if sbomFile == "" {
		return helpers.Errorf("sbomFile is required"), nil
	}
	flags := extractCommonFlags(m)
	extractSbomFlags(m, flags)
	return runScanner(ctx, "sbom", flags, sbomFile), nil
}

func runSARIF(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	sarifFile, _ := m["sarifFile"].(string)
	if sarifFile == "" {
		return helpers.Errorf("sarifFile is required"), nil
	}
	flags := extractCommonFlags(m)
	if v, ok := m["scannerID"].(string); ok && v != "" {
		flags["scannerID"] = v
	}
	return runScanner(ctx, "sarif", flags, sarifFile), nil
}

func runVEX(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	m, err := parseArgs(req)
	if err != nil {
		return helpers.Errorf("invalid arguments"), nil
	}
	vexFile, _ := m["vexFile"].(string)
	if vexFile == "" {
		return helpers.Errorf("vexFile is required"), nil
	}
	flags := extractCommonFlags(m)
	extractSbomFlags(m, flags)
	return runScanner(ctx, "vex", flags, vexFile), nil
}
