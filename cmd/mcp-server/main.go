package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcp-server/internal/api"
	"mcp-server/internal/config"
	"mcp-server/internal/tool/asset"
	"mcp-server/internal/tool/org"
	"mcp-server/internal/tool/project"
	"mcp-server/internal/tool/registry"
	"mcp-server/internal/tool/scanner"
	"mcp-server/internal/tool/vuln"
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
