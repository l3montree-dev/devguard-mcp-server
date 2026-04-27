package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const userAgent = "devguard-mcp-server"

// Client abstracts all HTTP communication with the DevGuard API.
type Client interface {
	Get(ctx context.Context, path string) ([]byte, error)
	Post(ctx context.Context, path string, body any) ([]byte, error)
}

type httpClient struct {
	baseURL string
	pat     string
	http    *http.Client
	logger  *slog.Logger
}

func NewClient(baseURL, pat string, logger *slog.Logger) Client {
	return &httpClient{
		baseURL: baseURL,
		pat:     pat,
		http:    &http.Client{Timeout: 30 * time.Second},
		logger:  logger,
	}
}

func (c *httpClient) Get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

func (c *httpClient) Post(ctx context.Context, path string, body any) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *httpClient) do(req *http.Request) ([]byte, error) {
	if err := signRequest(c.pat, req); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// Get is a typed helper: fetches path and decodes JSON into T.
func Get[T any](ctx context.Context, c Client, path string) (*T, error) {
	data, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// Post is a typed helper: posts body and decodes JSON response into T.
func Post[T any](ctx context.Context, c Client, path string, body any) (*T, error) {
	data, err := c.Post(ctx, path, body)
	if err != nil {
		return nil, err
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}
