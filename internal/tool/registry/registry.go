package registry

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler is the function signature expected by the MCP SDK.
type Handler = mcp.ToolHandler

type entry struct {
	tool    *mcp.Tool
	handler Handler
}

// Registry collects tools and registers them on an MCP server.
type Registry struct {
	entries []entry
}

func New() *Registry { return &Registry{} }

func (r *Registry) Add(tool *mcp.Tool, h Handler) {
	r.entries = append(r.entries, entry{tool: tool, handler: h})
}

func (r *Registry) RegisterAll(srv *mcp.Server) {
	for _, e := range r.entries {
		srv.AddTool(e.tool, e.handler)
	}
}
