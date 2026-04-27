package org

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
		Name:        "get_health",
		Description: "Get the health status of the DevGuard API",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	}, getHealth(client))

	r.Add(&mcp.Tool{
		Name:        "list_organizations",
		Description: "List all organizations the authenticated user has access to",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	}, listOrganizations(client))

	r.Add(&mcp.Tool{
		Name:        "create_organization",
		Description: "Create a new organization",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"Organization name"},"description":{"type":"string","description":"Organization description"},"language":{"type":"string","description":"Primary language"}},"required":["name"]}`),
	}, createOrganization(client))

	r.Add(&mcp.Tool{
		Name:        "prepare_scan_target",
		Description: "Call this tool FIRST whenever the user wants to run a DevGuard scan. It lists all existing assets across all organizations and projects so the user can pick one as the scan target, or decide to create a new one.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	}, prepareScanTarget(client))
}

func getHealth(client api.Client) registry.Handler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		health, err := api.Get[api.HealthResponse](ctx, client, "/health")
		if err != nil {
			return helpers.Errorf("Error fetching health status: %v", err), nil
		}
		if health.Error != "" {
			return helpers.Errorf("Health check error: %s", health.Error), nil
		}
		return helpers.Text(health.Status), nil
	}
}

func listOrganizations(client api.Client) registry.Handler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orgs, err := api.Get[[]api.OrgResponse](ctx, client, "/organizations")
		if err != nil {
			return helpers.Errorf("Error fetching organizations: %v", err), nil
		}
		return helpers.JSON(orgs), nil
	}
}

func createOrganization(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Language    string `json:"language"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		org, err := api.Post[api.OrgResponse](ctx, client, "/organizations", args)
		if err != nil {
			return helpers.Errorf("Error creating organization: %v", err), nil
		}
		return helpers.JSON(org), nil
	}
}

func prepareScanTarget(client api.Client) registry.Handler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orgs, err := api.Get[[]api.OrgResponse](ctx, client, "/organizations")
		if err != nil {
			return helpers.Errorf("Error fetching organizations: %v", err), nil
		}

		type entry struct {
			label       string
			orgSlug     string
			projectSlug string
			assetSlug   string
		}
		var entries []entry

		for _, o := range *orgs {
			projects, err := api.Get[[]api.ProjectResponse](ctx, client, fmt.Sprintf("/organizations/%s/content-tree", o.Slug))
			if err != nil {
				continue
			}
			for _, p := range *projects {
				assets, err := api.Get[[]api.AssetResponse](ctx, client, fmt.Sprintf("/organizations/%s/projects/%s/assets", o.Slug, p.Slug))
				if err != nil {
					continue
				}
				for _, a := range *assets {
					entries = append(entries, entry{
						label:       fmt.Sprintf("%s / %s / %s", o.Name, p.Name, a.Name),
						orgSlug:     o.Slug,
						projectSlug: p.Slug,
						assetSlug:   a.Slug,
					})
				}
			}
		}

		if len(entries) == 0 {
			return helpers.Text("No existing assets found in DevGuard.\n\nWould you like me to create a new organization, project, and asset for this scan?"), nil
		}

		var sb string
		sb = "Here are the existing DevGuard assets:\n\n"
		for i, e := range entries {
			sb += fmt.Sprintf("%d. %s  (org: %s, project: %s, asset: %s)\n", i+1, e.label, e.orgSlug, e.projectSlug, e.assetSlug)
		}
		sb += "\nWhich asset should the scan results be sent to? Or should I create a new one?"
		return helpers.Text(sb), nil
	}
}
