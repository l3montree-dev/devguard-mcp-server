# DevGuard MCP Server

> **⚠️ Proof of Concept**
> This is an early proof of concept and is not production-ready. It may contain bugs, missing features, and rough edges. It is intended for experimentation and feedback only — not for production use.
>
> We welcome your thoughts and feedback in the [GitHub Discussion](https://github.com/l3montree-dev/devguard/discussions/1906).

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that connects Claude and other MCP-compatible AI assistants to the [DevGuard](https://devguard.org) security platform.

It lets your AI assistant scan repositories for vulnerabilities, manage security findings, and triage risks — directly from the chat.

## Quick Start

| Step | What to do |
|------|------------|
| **1. Get a PAT** | Create a Personal Access Token in your [DevGuard account settings](https://app.devguard.org) |
| **2. Install the server** | Download the binary for your platform from the [Releases page](https://github.com/l3montree-dev/devguard-mcp-server/releases) |
| **3. Connect to your AI** | Add the server to any MCP-compatible AI client (Claude, Cursor, Copilot, etc.) with your PAT (see [Setup](#setup-in-claude-desktop) below) |

---

## What it can do

- List organizations, projects, and assets in DevGuard
- Run security scans: dependency (SCA), secrets, SAST, IaC, container images
- Upload SBOM, SARIF, and VEX documents
- List and assess vulnerabilities with detailed CVE/CVSS/EPSS data
- Accept risks or mark findings as false positives with justification

## Requirements

- A [DevGuard](https://devguard.org) account with a Personal Access Token (PAT)
- Any MCP-compatible AI client — Claude Desktop, Cursor, GitHub Copilot, Windsurf, or any other tool that supports MCP

## Installation

### Download the binary

Download the latest binary for your platform from the [Releases](https://github.com/l3montree-dev/devguard-mcp-server/releases) page:

| Platform | File |
|----------|------|
| Linux amd64 | `devguard-mcp-linux-amd64` |
| Linux arm64 | `devguard-mcp-linux-arm64` |
| macOS amd64 | `devguard-mcp-darwin-amd64` |
| macOS arm64 | `devguard-mcp-darwin-arm64` |
| Windows amd64 | `devguard-mcp-windows-amd64.exe` |
| Windows arm64 | `devguard-mcp-windows-arm64.exe` |

Make the binary executable (Linux/macOS):

```bash
chmod +x devguard-mcp-linux-amd64
```

### Build from source

```bash
git clone https://github.com/l3montree-dev/devguard/mcp-server
cd mcp-server
go build -o devguard-mcp ./cmd/mcp-server
```

## Configuration

The server requires a DevGuard Personal Access Token:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEVGUARD_PAT` | Yes | — | Your DevGuard Personal Access Token |
| `DEVGUARD_API_URL` | No | `https://api.devguard.org/api/v1` | Custom API URL (for self-hosted instances) |

You can set these as environment variables or in a `.env` file in the working directory.

## Setup

The DevGuard MCP server works with any MCP-compatible AI client. The examples below show Claude Desktop and Claude Code (VS Code), but the same approach applies to Cursor, GitHub Copilot, Windsurf, and others — refer to your client's MCP documentation for the exact config location.

## Setup in Claude Desktop

Add the following to your Claude Desktop config file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "devguard": {
      "command": "/path/to/devguard-mcp-*"
      "env": {
        "DEVGUARD_PAT": "your-pat-here",
        "DEVGUARD_API_URL": "https://your-self-hosted-instance/api/v1"
      }
    }
  }
}
```

Restart Claude Desktop — the DevGuard tools will be available in your next conversation.

## Setup in VS Code (Claude Code)

Add the server to your project or user config via the Claude Code CLI:

```bash
claude mcp add devguard /path/to/devguard-mcp -e DEVGUARD_PAT=your-pat-here
```

Or add it manually to `~/.claude.json` in your user directory:

```json
{
  "mcpServers": {
    "devguard": {
      "command": "/path/to/devguard-mcp-*",
      "env": {
        "DEVGUARD_PAT": "your-pat-here",
        "DEVGUARD_API_URL": "https://your-self-hosted-instance/api/v1"
      }
    }
  }
}
```

To verify the server was added successfully, run:

```bash
claude mcp list
```

You should see `devguard` listed. The tools will be available in your next Claude Code session.
