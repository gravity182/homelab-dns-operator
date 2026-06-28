// Package adguard provides an HTTP client for managing AdGuard Home rewrite rules.
package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RewriteEntry represents a DNS rewrite rule.
type RewriteEntry struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// Client provides methods for managing rewrite rules.
type Client struct {
	baseURL    string
	httpClient *http.Client
	auth       *BasicAuth
}

// BasicAuth contains credentials to use HTTP Basic Auth.
type BasicAuth struct {
	Username string
	Password string
}

// endpoints paths
const (
	endpointList   = "/rewrite/list"
	endpointAdd    = "/rewrite/add"
	endpointUpdate = "/rewrite/update"
	endpointDelete = "/rewrite/delete"
)

// NewClient creates a new [Client].
func NewClient(baseURL string, auth *BasicAuth, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		auth:       auth,
	}
}

// ListRewrites fetches all rewrite rules.
func (c *Client) ListRewrites(ctx context.Context) ([]RewriteEntry, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+endpointList,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var entries []RewriteEntry
	if err := c.do(req, &entries); err != nil {
		return nil, err
	}

	return entries, nil
}

// AddRewrite adds a new rewrite rule.
func (c *Client) AddRewrite(ctx context.Context, domain, answer string) error {
	newEntry := RewriteEntry{
		Domain: domain,
		Answer: answer,
	}
	requestBody, err := jsonBody(newEntry)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+endpointAdd,
		requestBody,
	)
	if err != nil {
		return err
	}

	return c.do(req, nil)
}

// UpdateRewrite updates an existing rewrite rule.
func (c *Client) UpdateRewrite(ctx context.Context, oldEntry, newEntry RewriteEntry) error {
	updateRequest := struct {
		Target RewriteEntry `json:"target"`
		Update RewriteEntry `json:"update"`
	}{
		Target: oldEntry,
		Update: newEntry,
	}
	requestBody, err := jsonBody(updateRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		c.baseURL+endpointUpdate,
		requestBody,
	)
	if err != nil {
		return err
	}

	return c.do(req, nil)
}

// DeleteRewrite deletes a rewrite rule.
func (c *Client) DeleteRewrite(ctx context.Context, domain, answer string) error {
	entry := RewriteEntry{
		Domain: domain,
		Answer: answer,
	}
	requestBody, err := jsonBody(entry)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+endpointDelete,
		requestBody,
	)
	if err != nil {
		return err
	}

	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.auth != nil {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("%s %s: unexpected status %d: %s", req.Method, req.URL.Path, resp.StatusCode, body)
	}
	if out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func jsonBody(v any) (io.Reader, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return nil, fmt.Errorf("encode json body: %w", err)
	}
	return &buf, nil
}
