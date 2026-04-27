package project

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
		Name:        "list_projects",
		Description: "List all projects within an organization",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"}},"required":["organization"]}`),
	}, listProjects(client))

	r.Add(&mcp.Tool{
		Name:        "create_project",
		Description: "Create a new project within an organization",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"organization":{"type":"string","description":"Organization slug"},"name":{"type":"string","description":"Project name"},"description":{"type":"string","description":"Project description"}},"required":["organization","name"]}`),
	}, createProject(client))
}

func listProjects(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		projects, err := api.Get[[]api.ProjectResponse](ctx, client, fmt.Sprintf("/organizations/%s/content-tree", args.Organization))
		if err != nil {
			return helpers.Errorf("Error fetching projects: %v", err), nil
		}
		return helpers.JSON(projects), nil
	}
}

func createProject(client api.Client) registry.Handler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Organization string `json:"organization"`
			Name         string `json:"name"`
			Description  string `json:"description"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return helpers.Errorf("invalid arguments"), nil
		}
		body := map[string]any{"name": args.Name, "description": args.Description}
		proj, err := api.Post[api.ProjectResponse](ctx, client, fmt.Sprintf("/organizations/%s/projects", args.Organization), body)
		if err != nil {
			return helpers.Errorf("Error creating project: %v", err), nil
		}
		return helpers.JSON(proj), nil
	}
}
