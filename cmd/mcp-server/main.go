package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/l3montree-dev/devguard-mcp-server/internal/api"
	"github.com/l3montree-dev/devguard-mcp-server/internal/config"
	"github.com/l3montree-dev/devguard-mcp-server/internal/tool/asset"
	"github.com/l3montree-dev/devguard-mcp-server/internal/tool/org"
	"github.com/l3montree-dev/devguard-mcp-server/internal/tool/project"
	"github.com/l3montree-dev/devguard-mcp-server/internal/tool/registry"
	"github.com/l3montree-dev/devguard-mcp-server/internal/tool/scanner"
	"github.com/l3montree-dev/devguard-mcp-server/internal/tool/vuln"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg := config.MustLoad()

	client := api.NewClient(cfg.APIBaseURL, cfg.PAT, logger)

	reg := registry.New()
	org.Register(reg, client)
	project.Register(reg, client)
	asset.Register(reg, client)
	vuln.Register(reg, client)
	scanner.Register(reg, client)

	logger.Info("starting devguard-mcp-server", "apiBaseURL", cfg.APIBaseURL)

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "devguard-mcp-server",
		Version: "0.0.1",
	}, nil)
	reg.RegisterAll(srv)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
