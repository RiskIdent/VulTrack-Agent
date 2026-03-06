package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Client handles communication with the VulTrack server
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
}

// EnrollmentRequest is the request body for enrollment
type EnrollmentRequest struct {
	Hostname string `json:"hostname"`
}

// EnrollmentResponse is the response from enrollment endpoint
type EnrollmentResponse struct {
	AgentToken string `json:"agentToken"`
	Status     string `json:"status"`
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
}

// Package represents a package in the report
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Source  string `json:"source"`
}

// ReportResponse is the response from report endpoint
type ReportResponse struct {
	Message      string `json:"message"`
	ServerID     int    `json:"serverId"`
	PackageCount int    `json:"packageCount"`
}

// APIError represents an API error response
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (%d): %s", e.StatusCode, e.Message)
}

// NewClient creates a new API client
func NewClient(baseURL string, insecure bool, caCertPath string) (*Client, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
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
		baseURL:    parsedURL,
		httpClient: client,
	}, nil
}

// Enroll enrolls the agent with the server
func (c *Client) Enroll(hostname, enrollmentKey string) (*EnrollmentResponse, error) {
	reqBody := EnrollmentRequest{
		Hostname: hostname,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := c.baseURL.JoinPath("/api/v1/agent/enroll")
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enrollment-Key", enrollmentKey)

	var resp *EnrollmentResponse
	err = c.doRequestWithRetry(req, &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Report sends a report to the server
func (c *Client) Report(token string, report *ReportRequest) (*ReportResponse, error) {
	jsonData, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := c.baseURL.JoinPath("/api/v1/agent/report")
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)

	var resp *ReportResponse
	err = c.doRequestWithRetry(req, &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// doRequestWithRetry performs an HTTP request with exponential backoff retry
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

		// Handle specific error codes
		if resp.StatusCode == 401 {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    "authentication failed: token invalid or expired",
			}
		}
		if resp.StatusCode == 403 {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    "agent access denied: agent may be pending or revoked",
			}
		}

		// For other errors, try to parse error message
		var errorMsg string
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err == nil {
			if msg, ok := errorResp["message"].(string); ok {
				errorMsg = msg
			} else if msg, ok := errorResp["error"].(string); ok {
				errorMsg = msg
			}
		}
		if errorMsg == "" {
			errorMsg = string(body)
		}

		if attempt == maxRetries {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    errorMsg,
			}
		}
	}

	return fmt.Errorf("request failed after %d retries", maxRetries)
}
