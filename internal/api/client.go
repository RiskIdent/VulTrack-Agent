package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Client handles communication with the VulTrack server.
// It manages the token lifecycle: enrollment, access token refresh, and
// automatic re-enrollment when the refresh token is rejected.
type Client struct {
	baseURL          *url.URL
	httpClient       *http.Client
	enrollmentKey    string
	refreshTokenFile string
	accessToken      string
	accessTokenExp   time.Time
	// pending is set while the server reports this registration as waiting
	// for admin approval. While it is set, a rejected token never leads to
	// a forced re-enrollment (see EnsureValidToken).
	pending bool
}

// EnrollmentRequest is the request body for enrollment
type EnrollmentRequest struct {
	Hostname string `json:"hostname"`
	Force    bool   `json:"force"`
}

// EnrollmentResponse is the response from the enrollment endpoint (HTTP 201)
type EnrollmentResponse struct {
	TokenType    string `json:"tokenType"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
	Status       string `json:"status"`
}

// TokenRefreshResponse is the response from the token refresh endpoint (HTTP 200)
type TokenRefreshResponse struct {
	TokenType    string `json:"tokenType"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
}

// ReportRequest is the request body for reporting
type ReportRequest struct {
	Hostname       string    `json:"hostname"`
	AgentVersion   string    `json:"agentVersion"`
	OSFamily       string    `json:"osFamily"`
	OSRelease      string    `json:"osRelease"`
	OSCodename     string    `json:"osCodename,omitempty"`
	Kernel         string    `json:"kernel"`
	Arch           string    `json:"arch"`
	PackageManager string    `json:"packageManager,omitempty"`
	IPv4Addrs      []string  `json:"ipv4Addrs"`
	ReportedAt     string    `json:"reportedAt,omitempty"`
	Packages       []Package `json:"packages"`
	// Runtime is the optional, pre-encoded runtime facts object.
	Runtime json.RawMessage `json:"runtime,omitempty"`
}

// Package represents a package in the report
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Source  string `json:"source"`
}

// ReportResponse is the response from the report endpoint
type ReportResponse struct {
	Message      string `json:"message"`
	ServerID     int    `json:"serverId"`
	PackageCount int    `json:"packageCount"`
	ScanJobID    string `json:"scanJobId"`
}

// Error codes the server sends in the "code" field of a 403 response for an
// agent whose registration is not active.
const (
	CodeAgentPending = "agent_pending"
	CodeAgentRevoked = "agent_revoked"
)

var (
	// ErrPendingApproval means the registration is waiting for admin approval.
	// The agent keeps its tokens and retries in the next cycle; it never
	// re-enrolls because of it.
	ErrPendingApproval = errors.New("agent is pending admin approval")
	// ErrAgentRevoked means an administrator revoked the registration. The
	// agent does not re-enroll on its own.
	ErrAgentRevoked = errors.New("agent registration was revoked by an administrator")
)

// APIError represents an API error response
type APIError struct {
	StatusCode int
	Message    string
	// Code is the machine-readable "code" field of the error body, if any.
	Code string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("API error (%d, %s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error (%d): %s", e.StatusCode, e.Message)
}

// Is lets errors.Is match a 403 response with a known code against
// ErrPendingApproval and ErrAgentRevoked.
func (e *APIError) Is(target error) bool {
	if e.StatusCode != http.StatusForbidden {
		return false
	}
	switch target {
	case ErrPendingApproval:
		return e.Code == CodeAgentPending
	case ErrAgentRevoked:
		return e.Code == CodeAgentRevoked
	}
	return false
}

// NewClient creates a new API client
func NewClient(baseURL string, insecure bool, caCertPath, enrollmentKey, refreshTokenFile string) (*Client, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec // controlled by --insecure flag
		},
	}

	// Load custom CA certificate if provided
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		transport.TLSClientConfig.RootCAs = caCertPool
		transport.TLSClientConfig.InsecureSkipVerify = false
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &Client{
		baseURL:          parsedURL,
		httpClient:       client,
		enrollmentKey:    enrollmentKey,
		refreshTokenFile: refreshTokenFile,
	}, nil
}

// Enroll enrolls the agent with the server (POST /api/v2/agent/enroll).
// Set force=true to revoke any existing registration and issue fresh tokens.
func (c *Client) Enroll(hostname string, force bool) (*EnrollmentResponse, error) {
	reqBody := EnrollmentRequest{
		Hostname: hostname,
		Force:    force,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := c.baseURL.JoinPath("/api/v2/agent/enroll")
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.enrollmentKey)

	var resp *EnrollmentResponse
	err = c.doRequestWithRetry(req, &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// RefreshAccessToken exchanges the current refresh token for new access and
// refresh tokens (POST /api/v2/agent/token). The submitted refresh token is
// revoked on use.
func (c *Client) RefreshAccessToken(refreshToken string) (*TokenRefreshResponse, error) {
	reqURL := c.baseURL.JoinPath("/api/v2/agent/token")
	req, err := http.NewRequest("POST", reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+refreshToken)

	var resp *TokenRefreshResponse
	err = c.doRequestWithRetry(req, &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Report sends a report to the server using the in-memory access token
// (POST /api/v2/agent/report).
func (c *Client) Report(report *ReportRequest) (*ReportResponse, error) {
	if c.accessToken == "" {
		return nil, &APIError{StatusCode: 401, Message: "no access token available"}
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := c.baseURL.JoinPath("/api/v2/agent/report")
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	var resp *ReportResponse
	err = c.doRequestWithRetry(req, &resp)
	if err != nil {
		if errors.Is(err, ErrPendingApproval) {
			c.pending = true
		}
		return nil, err
	}

	c.pending = false
	return resp, nil
}

// EnsureValidToken implements the token lifecycle state machine.
// Call this at the start of every report or daemon cycle.
//
//	START
//	  ├─ refresh_token_file does NOT exist or is empty
//	  │   └─ [A] Enroll → save refresh_token, hold access_token
//	  └─ refresh_token_file exists
//	      ├─ access_token in memory and not expired
//	      │   └─ [B] Use existing access_token
//	      └─ access_token absent or expired
//	          ├─ POST /api/v2/agent/token
//	          │   ├─ 200 OK  → [C] save new refresh_token, hold new access_token
//	          │   ├─ 403 agent_pending / agent_revoked
//	          │   │          → [F] return ErrPendingApproval / ErrAgentRevoked,
//	          │   │            never re-enroll
//	          │   └─ 401     → [D] Re-enroll with force=true, unless the agent is
//	          │                known to be pending approval: older servers answer
//	          │                401 for pending agents, and re-enrolling would
//	          │                replace the pending registration every cycle
//	          └─ network error → [E] return error (caller skips cycle)
func (c *Client) EnsureValidToken(hostname string) error {
	// [B] Access token is present and not expired — nothing to do.
	if c.accessToken != "" && time.Now().Before(c.accessTokenExp) {
		return nil
	}

	refreshToken, err := c.readRefreshToken()
	if err != nil {
		return fmt.Errorf("failed to read refresh token: %w", err)
	}

	if refreshToken == "" {
		// [A] No refresh token on disk — perform initial enrollment.
		return c.doEnroll(hostname, false)
	}

	// Try to exchange the refresh token for a new access token.
	refreshResp, err := c.RefreshAccessToken(refreshToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrPendingApproval):
			// [F] Still waiting for approval — keep the tokens, try again later.
			c.pending = true
			return fmt.Errorf("token refresh: %w", err)
		case errors.Is(err, ErrAgentRevoked):
			// [F] Revoked by an administrator — do not undo that by re-enrolling.
			return fmt.Errorf("token refresh: %w", err)
		}
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 401 {
			if c.pending {
				return fmt.Errorf("%w: the server rejected the refresh token; not re-enrolling while approval is pending", ErrPendingApproval)
			}
			// [D] Refresh token is expired or revoked — re-enroll automatically.
			return c.doEnroll(hostname, true)
		}
		// [E] Network or other error — caller should skip this cycle.
		return fmt.Errorf("token refresh failed: %w", err)
	}

	// [C] Refresh succeeded — persist new refresh token and hold new access token.
	c.pending = false
	return c.StoreTokens(refreshResp.AccessToken, refreshResp.ExpiresIn, refreshResp.RefreshToken)
}

// StoreTokens persists the refresh token to disk (write-then-rename) and
// holds the access token in memory. Call this after enrollment or token refresh.
func (c *Client) StoreTokens(accessToken string, expiresIn int, refreshToken string) error {
	if err := c.writeRefreshToken(refreshToken); err != nil {
		return err
	}
	c.accessToken = accessToken
	c.accessTokenExp = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return nil
}

// InvalidateAccessToken clears the in-memory access token, forcing
// EnsureValidToken to perform a real refresh on the next call.
// Call this when the server rejects the current token with 401.
func (c *Client) InvalidateAccessToken() {
	c.accessToken = ""
	c.accessTokenExp = time.Time{}
}

// HasRefreshToken reports whether the refresh token file exists on disk.
func (c *Client) HasRefreshToken() bool {
	_, err := os.Stat(c.refreshTokenFile)
	return err == nil
}

// TokenPrefix returns the first 8 characters of a token for safe logging.
func TokenPrefix(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "..."
}

// doEnroll is used internally by EnsureValidToken to enroll (or re-enroll)
// the agent and store the resulting tokens.
func (c *Client) doEnroll(hostname string, force bool) error {
	if c.enrollmentKey == "" {
		return fmt.Errorf("enrollment_key is not configured; cannot enroll or re-enroll automatically — set it in the config file or via --enrollment-key / VULTRACK_ENROLLMENT_KEY")
	}
	resp, err := c.Enroll(hostname, force)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	if err := c.StoreTokens(resp.AccessToken, resp.ExpiresIn, resp.RefreshToken); err != nil {
		return err
	}

	c.pending = resp.Status == "pending"
	if c.pending {
		return fmt.Errorf("enrolled, %w; reports will be sent once approved", ErrPendingApproval)
	}

	return nil
}

// readRefreshToken reads the refresh token from disk.
// Returns ("", nil) if the file does not exist.
func (c *Client) readRefreshToken() (string, error) {
	data, err := os.ReadFile(c.refreshTokenFile)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// writeRefreshToken atomically writes the refresh token to disk using a
// write-then-rename pattern to avoid corrupt state if the process is killed
// mid-write. File permissions are set to 0600.
func (c *Client) writeRefreshToken(token string) error {
	if err := c.ensureRefreshTokenDir(); err != nil {
		return fmt.Errorf("failed to create refresh token directory: %w", err)
	}

	tmp := c.refreshTokenFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write refresh token: %w", err)
	}
	if err := os.Rename(tmp, c.refreshTokenFile); err != nil {
		return fmt.Errorf("failed to rename refresh token file: %w", err)
	}
	return nil
}

// ensureRefreshTokenDir ensures the parent directory of the refresh token
// file exists with permissions 0700.
func (c *Client) ensureRefreshTokenDir() error {
	dir := filepath.Dir(c.refreshTokenFile)
	return os.MkdirAll(dir, 0700)
}

// doRequestWithRetry performs an HTTP request with exponential backoff retry.
// 4xx client errors are never retried — they indicate a problem the caller must resolve.
func (c *Client) doRequestWithRetry(req *http.Request, respBody interface{}) error {
	maxRetries := 3
	backoff := time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff

			// Reset the request body for retry — the body reader is consumed after
			// the first Do() call, so we need a fresh reader from GetBody.
			if req.GetBody != nil {
				newBody, err := req.GetBody()
				if err != nil {
					return fmt.Errorf("failed to reset request body for retry: %w", err)
				}
				req.Body = newBody
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if attempt == maxRetries {
				return fmt.Errorf("request failed after %d retries: %w", maxRetries, err)
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if respBody != nil {
				if err := json.Unmarshal(body, respBody); err != nil {
					return fmt.Errorf("failed to unmarshal response: %w", err)
				}
			}
			return nil
		}

		// Parse error message and code from response body
		errorMsg, errorCode := parseError(body)

		// Never retry client errors (4xx) — the caller must handle them.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    errorMsg,
				Code:       errorCode,
			}
		}

		// 5xx and other errors: retry up to maxRetries
		if attempt == maxRetries {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    errorMsg,
				Code:       errorCode,
			}
		}
	}

	return fmt.Errorf("request failed after %d retries", maxRetries)
}

// parseError extracts the message ("message" or "error") and the optional
// machine-readable "code" from an error response body.
func parseError(body []byte) (message, code string) {
	var errorResp map[string]interface{}
	if err := json.Unmarshal(body, &errorResp); err == nil {
		code, _ = errorResp["code"].(string)
		if msg, ok := errorResp["message"].(string); ok {
			return msg, code
		}
		if msg, ok := errorResp["error"].(string); ok {
			return msg, code
		}
	}
	return string(body), code
}
