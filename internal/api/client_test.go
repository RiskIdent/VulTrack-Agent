package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

// --- APIError ---

func TestAPIError_Error(t *testing.T) {
	err := &APIError{StatusCode: 401, Message: "authentication failed"}
	want := "API error (401): authentication failed"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// --- NewClient ---

func TestNewClient_Default(t *testing.T) {
	client, err := NewClient("https://example.com", false, "")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewClient_Insecure(t *testing.T) {
	client, err := NewClient("https://example.com", true, "")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewClient_InvalidCACert(t *testing.T) {
	_, err := NewClient("https://example.com", false, "/nonexistent/ca.crt")
	if err == nil {
		t.Error("expected error for nonexistent CA cert")
	}
}

func TestNewClient_InvalidCACertContent(t *testing.T) {
	f := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(f, []byte("not a valid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewClient("https://example.com", false, f)
	if err == nil {
		t.Error("expected error for invalid CA cert content")
	}
}

// --- Enroll ---

func TestEnroll_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/agent/enroll" {
			t.Errorf("path = %q, want /api/v1/agent/enroll", r.URL.Path)
		}
		if r.Header.Get("X-Enrollment-Key") != "test-enrollment-key" {
			t.Errorf("X-Enrollment-Key = %q", r.Header.Get("X-Enrollment-Key"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}

		var req EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Hostname != "test-host" {
			t.Errorf("Hostname = %q, want test-host", req.Hostname)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EnrollmentResponse{
			AgentToken: "secret-token-123",
			Status:     "active",
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, true, "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Enroll("test-host", "test-enrollment-key")
	if err != nil {
		t.Fatalf("Enroll error: %v", err)
	}
	if resp.AgentToken != "secret-token-123" {
		t.Errorf("AgentToken = %q, want secret-token-123", resp.AgentToken)
	}
	if resp.Status != "active" {
		t.Errorf("Status = %q, want active", resp.Status)
	}
}

func TestEnroll_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "invalid key"})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Enroll("test-host", "bad-key")
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
}

func TestEnroll_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Enroll("test-host", "key")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
}

// --- Report ---

func TestReport_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/report" {
			t.Errorf("path = %q, want /api/v1/agent/report", r.URL.Path)
		}
		if r.Header.Get("X-Agent-Token") != "my-token" {
			t.Errorf("X-Agent-Token = %q", r.Header.Get("X-Agent-Token"))
		}

		var req ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Hostname != "test-host" {
			t.Errorf("Hostname = %q", req.Hostname)
		}
		if len(req.Packages) != 2 {
			t.Errorf("Packages count = %d, want 2", len(req.Packages))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ReportResponse{
			Message:      "ok",
			ServerID:     42,
			PackageCount: 2,
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	report := &ReportRequest{
		Hostname:     "test-host",
		AgentVersion: "1.0.0",
		OSFamily:     "ubuntu",
		OSRelease:    "22.04",
		Kernel:       "5.15.0",
		Arch:         "amd64",
		IPv4Addrs:    []string{"10.0.0.1"},
		Packages: []Package{
			{Name: "bash", Version: "5.1", Arch: "amd64", Source: "bash"},
			{Name: "curl", Version: "7.81", Arch: "amd64", Source: "curl"},
		},
	}

	resp, err := client.Report("my-token", report)
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}
	if resp.ServerID != 42 {
		t.Errorf("ServerID = %d, want 42", resp.ServerID)
	}
	if resp.PackageCount != 2 {
		t.Errorf("PackageCount = %d, want 2", resp.PackageCount)
	}
}

func TestReport_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Report("bad-token", &ReportRequest{})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
}

func TestReport_ServerError_ParsesErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "internal error"})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Report("token", &ReportRequest{})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
	if apiErr.Message != "internal error" {
		t.Errorf("Message = %q, want 'internal error'", apiErr.Message)
	}
}

// --- Retry ---

func TestReport_RetryOnServerError_SucceedsOnSecondAttempt(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ReportResponse{ServerID: 1, PackageCount: 0})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Report("token", &ReportRequest{})
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d, want 2", attempts.Load())
	}
}

func TestEnroll_NoRetryOn401(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Enroll("host", "bad-key")
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 401)", attempts.Load())
	}
}

func TestEnroll_NoRetryOn403(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "")
	_, err := client.Enroll("host", "key")
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 403)", attempts.Load())
	}
}
