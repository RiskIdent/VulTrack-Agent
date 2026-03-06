package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.TokenFile != "/etc/vultrack-agent/token" {
		t.Errorf("unexpected TokenFile: %q", cfg.TokenFile)
	}
	if cfg.ReportInterval != time.Hour {
		t.Errorf("unexpected ReportInterval: %v", cfg.ReportInterval)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("unexpected LogLevel: %q", cfg.LogLevel)
	}
	if cfg.Insecure {
		t.Error("Insecure should default to false")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid https config",
			cfg: Config{
				ServerURL:      "https://example.com",
				TokenFile:      "/tmp/token",
				ReportInterval: time.Hour,
				LogLevel:       "info",
			},
		},
		{
			name: "valid http with insecure",
			cfg: Config{
				ServerURL:      "http://example.com",
				TokenFile:      "/tmp/token",
				ReportInterval: time.Hour,
				LogLevel:       "info",
				Insecure:       true,
			},
		},
		{
			name:    "missing server_url",
			cfg:     Config{TokenFile: "/tmp/token", ReportInterval: time.Hour, LogLevel: "info"},
			wantErr: true,
		},
		{
			name: "http without insecure",
			cfg: Config{
				ServerURL:      "http://example.com",
				TokenFile:      "/tmp/token",
				ReportInterval: time.Hour,
				LogLevel:       "info",
			},
			wantErr: true,
		},
		{
			name:    "missing token_file",
			cfg:     Config{ServerURL: "https://example.com", ReportInterval: time.Hour, LogLevel: "info"},
			wantErr: true,
		},
		{
			name: "zero report_interval",
			cfg: Config{
				ServerURL: "https://example.com",
				TokenFile: "/tmp/token",
				LogLevel:  "info",
			},
			wantErr: true,
		},
		{
			name: "invalid log_level",
			cfg: Config{
				ServerURL:      "https://example.com",
				TokenFile:      "/tmp/token",
				ReportInterval: time.Hour,
				LogLevel:       "verbose",
			},
			wantErr: true,
		},
		{
			name: "log_level case insensitive",
			cfg: Config{
				ServerURL:      "https://example.com",
				TokenFile:      "/tmp/token",
				ReportInterval: time.Hour,
				LogLevel:       "DEBUG",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("VULTRACK_SERVER_URL", "https://env.example.com")
	t.Setenv("VULTRACK_ENROLLMENT_KEY", "env-key")
	t.Setenv("VULTRACK_TOKEN_FILE", "/tmp/env-token")
	t.Setenv("VULTRACK_REPORT_INTERVAL", "30m")
	t.Setenv("VULTRACK_LOG_LEVEL", "debug")
	t.Setenv("VULTRACK_LOG_FILE", "/tmp/agent.log")
	t.Setenv("VULTRACK_INSECURE", "true")
	t.Setenv("VULTRACK_CA_CERT", "/tmp/ca.crt")

	cfg := DefaultConfig()
	cfg.LoadFromEnv()

	if cfg.ServerURL != "https://env.example.com" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.EnrollmentKey != "env-key" {
		t.Errorf("EnrollmentKey = %q", cfg.EnrollmentKey)
	}
	if cfg.TokenFile != "/tmp/env-token" {
		t.Errorf("TokenFile = %q", cfg.TokenFile)
	}
	if cfg.ReportInterval != 30*time.Minute {
		t.Errorf("ReportInterval = %v", cfg.ReportInterval)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.LogFile != "/tmp/agent.log" {
		t.Errorf("LogFile = %q", cfg.LogFile)
	}
	if !cfg.Insecure {
		t.Error("Insecure should be true")
	}
	if cfg.CACert != "/tmp/ca.crt" {
		t.Errorf("CACert = %q", cfg.CACert)
	}
}

func TestLoadFromEnv_EmptyVarsDoNotOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogLevel = "warn"
	cfg.LoadFromEnv() // no env vars set
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel should not be overridden by empty env var, got %q", cfg.LogLevel)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `server_url: https://file.example.com
enrollment_key: file-key
token_file: /tmp/file-token
log_level: warn
insecure: false
`
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg := DefaultConfig()
	if err := cfg.LoadFromFile(f.Name()); err != nil {
		t.Fatalf("LoadFromFile error: %v", err)
	}

	if cfg.ServerURL != "https://file.example.com" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.EnrollmentKey != "file-key" {
		t.Errorf("EnrollmentKey = %q", cfg.EnrollmentKey)
	}
	if cfg.TokenFile != "/tmp/file-token" {
		t.Errorf("TokenFile = %q", cfg.TokenFile)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
}

func TestLoadFromFile_NotExist(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.LoadFromFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist error, got: %v", err)
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{invalid: yaml: content")
	f.Close()

	cfg := DefaultConfig()
	if err := cfg.LoadFromFile(f.Name()); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfig_Priority(t *testing.T) {
	// File sets server_url to file value
	content := "server_url: https://file.example.com\nlog_level: error\n"
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()

	// Env overrides log_level
	t.Setenv("VULTRACK_LOG_LEVEL", "warn")
	t.Setenv("VULTRACK_SERVER_URL", "https://env.example.com")

	// Flag overrides server_url
	overrides := map[string]string{
		"server_url": "https://flag.example.com",
	}

	cfg, err := LoadConfig(f.Name(), overrides)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	// Flag wins over env and file for server_url
	if cfg.ServerURL != "https://flag.example.com" {
		t.Errorf("ServerURL = %q, want flag value", cfg.ServerURL)
	}
	// Env wins over file for log_level
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want env value", cfg.LogLevel)
	}
}

func TestLoadConfig_MissingFileIsOK(t *testing.T) {
	// A missing config file must not cause an error; required fields are
	// satisfied via overrides so that validation passes.
	overrides := map[string]string{"server_url": "https://example.com"}
	cfg, err := LoadConfig("/nonexistent/config.yaml", overrides)
	if err != nil {
		t.Fatalf("LoadConfig should not fail for missing file, got: %v", err)
	}
	// Should use defaults for unset fields
	if cfg.ReportInterval != time.Hour {
		t.Errorf("ReportInterval = %v, want 1h", cfg.ReportInterval)
	}
}

func TestEnsureTokenDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "nested")
	cfg := &Config{TokenFile: filepath.Join(dir, "token")}
	if err := cfg.EnsureTokenDir(); err != nil {
		t.Fatalf("EnsureTokenDir error: %v", err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}
