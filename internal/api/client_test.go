package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	client, err := NewClient("https://example.com", false, "", "", "")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewClient_Insecure(t *testing.T) {
	client, err := NewClient("https://example.com", true, "", "", "")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewClient_InvalidCACert(t *testing.T) {
	_, err := NewClient("https://example.com", false, "/nonexistent/ca.crt", "", "")
	if err == nil {
		t.Error("expected error for nonexistent CA cert")
	}
}

func TestNewClient_InvalidCACertContent(t *testing.T) {
	f := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(f, []byte("not a valid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewClient("https://example.com", false, f, "", "")
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
		if r.URL.Path != "/api/v2/agent/enroll" {
			t.Errorf("path = %q, want /api/v2/agent/enroll", r.URL.Path)
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Errorf("Authorization header = %q, want Bearer prefix", authHeader)
		}
		if authHeader != "Bearer enroll_test-key" {
			t.Errorf("Authorization = %q, want 'Bearer enroll_test-key'", authHeader)
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
		if req.Force {
			t.Error("Force should be false for initial enrollment")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			TokenType:    "Bearer",
			AccessToken:  "access-jwt-token",
			RefreshToken: "rt_refreshtoken123",
			ExpiresIn:    86400,
			Status:       "active",
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, true, "", "enroll_test-key", "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Enroll("test-host", false)
	if err != nil {
		t.Fatalf("Enroll error: %v", err)
	}
	if resp.AccessToken != "access-jwt-token" {
		t.Errorf("AccessToken = %q, want access-jwt-token", resp.AccessToken)
	}
	if resp.RefreshToken != "rt_refreshtoken123" {
		t.Errorf("RefreshToken = %q, want rt_refreshtoken123", resp.RefreshToken)
	}
	if resp.Status != "active" {
		t.Errorf("Status = %q, want active", resp.Status)
	}
}

func TestEnroll_Force(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if !req.Force {
			t.Error("Force should be true for force re-enrollment")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			TokenType:    "Bearer",
			AccessToken:  "new-access-token",
			RefreshToken: "rt_newrefresh",
			ExpiresIn:    86400,
			Status:       "active",
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "enroll_key", "")
	resp, err := client.Enroll("test-host", true)
	if err != nil {
		t.Fatalf("Enroll(force=true) error: %v", err)
	}
	if resp.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
}

func TestEnroll_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "invalid key"})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "bad-key", "")
	_, err := client.Enroll("test-host", false)
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

func TestEnroll_Conflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"message": "hostname already registered"})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "enroll_key", "")
	_, err := client.Enroll("test-host", false)
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 409 {
		t.Errorf("StatusCode = %d, want 409", apiErr.StatusCode)
	}
}

func TestEnroll_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "key", "")
	_, err := client.Enroll("test-host", false)
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
}

// --- RefreshAccessToken ---

func TestRefreshAccessToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/api/v2/agent/token" {
			t.Errorf("path = %q, want /api/v2/agent/token", r.URL.Path)
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer rt_oldrefreshtoken" {
			t.Errorf("Authorization = %q, want 'Bearer rt_oldrefreshtoken'", authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenRefreshResponse{
			TokenType:    "Bearer",
			AccessToken:  "new-access-jwt",
			RefreshToken: "rt_newrefreshtoken",
			ExpiresIn:    86400,
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "", "")
	resp, err := client.RefreshAccessToken("rt_oldrefreshtoken")
	if err != nil {
		t.Fatalf("RefreshAccessToken error: %v", err)
	}
	if resp.AccessToken != "new-access-jwt" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
	if resp.RefreshToken != "rt_newrefreshtoken" {
		t.Errorf("RefreshToken = %q", resp.RefreshToken)
	}
}

func TestRefreshAccessToken_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "refresh token expired"})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "", "")
	_, err := client.RefreshAccessToken("rt_expiredtoken")
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

// --- Report ---

func TestReport_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/agent/report" {
			t.Errorf("path = %q, want /api/v2/agent/report", r.URL.Path)
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer my-access-token" {
			t.Errorf("Authorization = %q, want 'Bearer my-access-token'", authHeader)
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
			Message:      "Report processed successfully",
			ServerID:     42,
			PackageCount: 2,
			ScanJobID:    "scan-uuid-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "", "")
	client.accessToken = "my-access-token"
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

	resp, err := client.Report(report)
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}
	if resp.ServerID != 42 {
		t.Errorf("ServerID = %d, want 42", resp.ServerID)
	}
	if resp.PackageCount != 2 {
		t.Errorf("PackageCount = %d, want 2", resp.PackageCount)
	}
	if resp.ScanJobID != "scan-uuid-123" {
		t.Errorf("ScanJobID = %q, want scan-uuid-123", resp.ScanJobID)
	}
}

func TestReport_NoAccessToken(t *testing.T) {
	client, _ := NewClient("https://example.com", true, "", "", "")
	// accessToken is empty — should return 401 without making a network call
	_, err := client.Report(&ReportRequest{})
	if err == nil {
		t.Fatal("expected error with empty access token")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
}

func TestReport_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "", "")
	client.accessToken = "expired-token"
	_, err := client.Report(&ReportRequest{})
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

	client, _ := NewClient(server.URL, true, "", "", "")
	client.accessToken = "valid-token"
	_, err := client.Report(&ReportRequest{})
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

	client, _ := NewClient(server.URL, true, "", "", "")
	client.accessToken = "valid-token"
	_, err := client.Report(&ReportRequest{})
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

	client, _ := NewClient(server.URL, true, "", "bad-key", "")
	_, err := client.Enroll("host", false)
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

	client, _ := NewClient(server.URL, true, "", "key", "")
	_, err := client.Enroll("host", false)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 403)", attempts.Load())
	}
}

func TestEnroll_NoRetryOn409(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "key", "")
	_, err := client.Enroll("host", false)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 409)", attempts.Load())
	}
}

// --- Token lifecycle state machine (EnsureValidToken) ---

func TestEnsureValidToken_UsesExistingAccessToken(t *testing.T) {
	// No server needed — the client should use the in-memory token without
	// making any network calls.
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, true, "", "enroll_key", "")
	client.accessToken = "valid-token"
	client.accessTokenExp = futureTime()

	if err := client.EnsureValidToken("host"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if serverCalled {
		t.Error("server should not have been called when access token is valid")
	}
}

func TestEnsureValidToken_EnrollsWhenNoRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/agent/enroll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			TokenType:    "Bearer",
			AccessToken:  "new-access-token",
			RefreshToken: "rt_newtoken",
			ExpiresIn:    86400,
			Status:       "active",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	rtFile := filepath.Join(dir, "refresh.token")

	client, _ := NewClient(server.URL, true, "", "enroll_key", rtFile)

	if err := client.EnsureValidToken("host"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.accessToken != "new-access-token" {
		t.Errorf("accessToken = %q, want new-access-token", client.accessToken)
	}

	// Refresh token should be written to disk
	data, err := os.ReadFile(rtFile)
	if err != nil {
		t.Fatalf("refresh token file not written: %v", err)
	}
	if strings.TrimSpace(string(data)) != "rt_newtoken" {
		t.Errorf("refresh token on disk = %q, want rt_newtoken", strings.TrimSpace(string(data)))
	}
}

func TestEnsureValidToken_RefreshesExpiredAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/agent/token" {
			t.Errorf("expected /api/v2/agent/token, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer rt_existingtoken" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenRefreshResponse{
			TokenType:    "Bearer",
			AccessToken:  "refreshed-access-token",
			RefreshToken: "rt_rotatedtoken",
			ExpiresIn:    86400,
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	rtFile := filepath.Join(dir, "refresh.token")
	if err := os.WriteFile(rtFile, []byte("rt_existingtoken"), 0600); err != nil {
		t.Fatal(err)
	}

	client, _ := NewClient(server.URL, true, "", "enroll_key", rtFile)
	// access token is absent (expired / not set)

	if err := client.EnsureValidToken("host"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.accessToken != "refreshed-access-token" {
		t.Errorf("accessToken = %q, want refreshed-access-token", client.accessToken)
	}

	// New refresh token should be written to disk
	data, _ := os.ReadFile(rtFile)
	if strings.TrimSpace(string(data)) != "rt_rotatedtoken" {
		t.Errorf("refresh token on disk = %q, want rt_rotatedtoken", strings.TrimSpace(string(data)))
	}
}

func TestEnsureValidToken_ReEnrollsWhenRefreshReturns401(t *testing.T) {
	var paths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)

		if r.URL.Path == "/api/v2/agent/token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v2/agent/enroll" {
			var req EnrollmentRequest
			json.NewDecoder(r.Body).Decode(&req)
			if !req.Force {
				t.Error("re-enrollment should use force=true")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EnrollmentResponse{
				TokenType:    "Bearer",
				AccessToken:  "reenrolled-token",
				RefreshToken: "rt_reenrolled",
				ExpiresIn:    86400,
				Status:       "active",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	dir := t.TempDir()
	rtFile := filepath.Join(dir, "refresh.token")
	if err := os.WriteFile(rtFile, []byte("rt_revokedtoken"), 0600); err != nil {
		t.Fatal(err)
	}

	client, _ := NewClient(server.URL, true, "", "enroll_key", rtFile)

	if err := client.EnsureValidToken("host"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have tried refresh first, then re-enrolled
	if len(paths) != 2 || paths[0] != "/api/v2/agent/token" || paths[1] != "/api/v2/agent/enroll" {
		t.Errorf("request paths = %v, want [/api/v2/agent/token /api/v2/agent/enroll]", paths)
	}
	if client.accessToken != "reenrolled-token" {
		t.Errorf("accessToken = %q, want reenrolled-token", client.accessToken)
	}
	data, _ := os.ReadFile(rtFile)
	if strings.TrimSpace(string(data)) != "rt_reenrolled" {
		t.Errorf("refresh token on disk = %q, want rt_reenrolled", strings.TrimSpace(string(data)))
	}
}

// --- Atomic token file write (write-then-rename) ---

func TestWriteRefreshToken_AtomicWriteThenRename(t *testing.T) {
	dir := t.TempDir()
	rtFile := filepath.Join(dir, "refresh.token")

	client, _ := NewClient("https://example.com", true, "", "", rtFile)

	if err := client.writeRefreshToken("rt_atomictest"); err != nil {
		t.Fatalf("writeRefreshToken error: %v", err)
	}

	// The final file must exist with the correct content
	data, err := os.ReadFile(rtFile)
	if err != nil {
		t.Fatalf("refresh token file not found: %v", err)
	}
	if strings.TrimSpace(string(data)) != "rt_atomictest" {
		t.Errorf("content = %q, want rt_atomictest", strings.TrimSpace(string(data)))
	}

	// The temporary file must not remain
	if _, err := os.Stat(rtFile + ".tmp"); err == nil {
		t.Error("tmp file should have been renamed away")
	}

	// File permissions must be 0600
	info, err := os.Stat(rtFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteRefreshToken_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	rtFile := filepath.Join(dir, "subdir", "refresh.token")

	client, _ := NewClient("https://example.com", true, "", "", rtFile)

	if err := client.writeRefreshToken("rt_dirtest"); err != nil {
		t.Fatalf("writeRefreshToken error: %v", err)
	}

	if _, err := os.Stat(filepath.Dir(rtFile)); os.IsNotExist(err) {
		t.Error("parent directory was not created")
	}
}

func TestTokenPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"enroll_abc123def456", "enroll_a..."},
		{"short", "short"},
		{"exactly8", "exactly8"},
		{"exactly9x", "exactly9..."},
	}
	for _, tt := range tests {
		got := TokenPrefix(tt.input)
		if got != tt.want {
			t.Errorf("TokenPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// futureTime returns a time well in the future, for use in tests that need
// an access token that has not yet expired.
func futureTime() time.Time {
	return time.Now().Add(24 * time.Hour)
}
