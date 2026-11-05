package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vultrack/vultrack-agent/internal/api"
	"github.com/vultrack/vultrack-agent/internal/config"
)

// The module index state file is written only after the server accepted the
// report with HTTP 2xx.
func TestSubmitReportModuleIndexState(t *testing.T) {
	status := http.StatusBadRequest
	var got map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = nil
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"ok","serverId":1,"packageCount":0}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ModuleIndexStateFile = filepath.Join(dir, "module-index.sha256")

	client, err := api.NewClient(srv.URL, true, "", "key", filepath.Join(dir, "refresh.token"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.StoreTokens("access", 3600, "rt_refresh"); err != nil {
		t.Fatal(err)
	}
	report := &api.ReportRequest{Hostname: "h", Runtime: json.RawMessage(`{"schemaVersion":1}`)}

	if _, err := submitReport(cfg, client, "h", report, "sha256:abc"); err == nil {
		t.Fatal("expected the report to fail")
	}
	if _, err := os.Stat(cfg.ModuleIndexStateFile); !os.IsNotExist(err) {
		t.Fatal("state file must not be written when the report fails")
	}
	if string(got["runtime"]) != `{"schemaVersion":1}` {
		t.Errorf("runtime not sent: %s", got["runtime"])
	}

	status = http.StatusOK
	if _, err := submitReport(cfg, client, "h", report, "sha256:abc"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.ModuleIndexStateFile)
	if err != nil || strings.TrimSpace(string(data)) != "sha256:abc" {
		t.Fatalf("state file after success: %q, %v", data, err)
	}

	// A hash-only report ("" hash) leaves the state file untouched.
	if _, err := submitReport(cfg, client, "h", report, ""); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(cfg.ModuleIndexStateFile); strings.TrimSpace(string(data)) != "sha256:abc" {
		t.Error("state file changed by a hash-only report")
	}
}

func TestReportWithoutRuntimeOmitsField(t *testing.T) {
	b, err := json.Marshal(&api.ReportRequest{Hostname: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "runtime") {
		t.Errorf("runtime must be omitted when not collected: %s", b)
	}
}
