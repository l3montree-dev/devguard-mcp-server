package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcp-server/internal/api"
	"mcp-server/internal/tool/helpers"
	"mcp-server/internal/tool/registry"
)

func Register(r *registry.Registry, client api.Client) {
	r.Add(&mcp.Tool{
		Name:        "list_assets",
		Description: "List all assets within a project",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"}},"required":["organization","project"]}`),
	}, listAssets(client))

	r.Add(&mcp.Tool{
		Name:        "list_asset_versions",
		Description: "List all asset versions (refs/branches) for an asset",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"},"asset":{"type":"string","description":"Asset slug"}},"required":["organization","project","asset"]}`),
	}, listAssetVersions(client))

	r.Add(&mcp.Tool{
		Name:        "create_asset",
		Description: "Create a new asset within a project",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"project":{"type":"string","description":"Project slug"},"name":{"type":"string","description":"Asset name"},"description":{"type":"string","description":"Asset description"},"confidentialityRequirement":{"type":"string","description":"Confidentiality requirement: low, medium, or high","enum":["low","medium","high"]},"integrityRequirement":{"type":"string","description":"Integrity requirement: low, medium, or high","enum":["low","medium","high"]},"availabilityRequirement":{"type":"string","description":"Availability requirement: low, medium, or high","enum":["low","medium","high"]}},"required":["organization","project","name","confidentialityRequirement","integrityRequirement","availabilityRequirement"]}`),
	}, createAsset(client))
}

func listAssets(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
			Project      string `json:"project"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		assets, err := api.Get[[]api.AssetResponse](ctx, client, fmt.Sprintf("/organizations/%s/projects/%s/assets", args.Organization, args.Project))
		if err != nil {
			return helpers.Errorf("Error fetching assets: %v", err), nil
		}
		return helpers.JSON(assets), nil
	}
}

func listAssetVersions(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
			Project      string `json:"project"`
			Asset        string `json:"asset"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		versions, err := api.Get[[]api.AssetVersionResponse](ctx, client, fmt.Sprintf("/organizations/%s/projects/%s/assets/%s/refs/", args.Organization, args.Project, args.Asset))
		if err != nil {
			return helpers.Errorf("Error fetching asset versions: %v", err), nil
		}
		return helpers.JSON(versions), nil
	}
}

func createAsset(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization               string `json:"organization"`
			Project                    string `json:"project"`
			Name                       string `json:"name"`
			Description                string `json:"description"`
			ConfidentialityRequirement string `json:"confidentialityRequirement"`
			IntegrityRequirement       string `json:"integrityRequirement"`
			AvailabilityRequirement    string `json:"availabilityRequirement"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		body := map[string]any{
			"name":                       args.Name,
			"description":                args.Description,
			"confidentialityRequirement": args.ConfidentialityRequirement,
			"integrityRequirement":       args.IntegrityRequirement,
			"availabilityRequirement":    args.AvailabilityRequirement,
		}
		a, err := api.Post[api.AssetResponse](ctx, client, fmt.Sprintf("/organizations/%s/projects/%s/assets", args.Organization, args.Project), body)
		if err != nil {
			return helpers.Errorf("Error creating asset: %v", err), nil
		}
		return helpers.JSON(a), nil
	}
}
