package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

// Config holds all configuration for the agent
type Config struct {
	ServerURL        string        `yaml:"server_url" env:"VULTRACK_SERVER_URL"`
	// EnrollmentKey is required for enrollment and automatic re-enrollment.
	// Keep this value permanently in the config — it is needed to re-enroll
	// when the refresh token expires or is revoked.
	EnrollmentKey    string        `yaml:"enrollment_key" env:"VULTRACK_ENROLLMENT_KEY"`
	RefreshTokenFile string        `yaml:"refresh_token_file" env:"VULTRACK_REFRESH_TOKEN_FILE"`
	ReportInterval   time.Duration `yaml:"report_interval" env:"VULTRACK_REPORT_INTERVAL"`
	LogLevel         string        `yaml:"log_level" env:"VULTRACK_LOG_LEVEL"`
	LogFile          string        `yaml:"log_file" env:"VULTRACK_LOG_FILE"`
	Insecure         bool          `yaml:"insecure" env:"VULTRACK_INSECURE"`
	CACert           string        `yaml:"ca_cert" env:"VULTRACK_CA_CERT"`
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	return &Config{
		RefreshTokenFile: "/var/lib/vultrack-agent/refresh.token",
		ReportInterval:   1 * time.Hour,
		LogLevel:         "info",
		LogFile:          "",
		Insecure:         false,
	}
}

// LoadConfig loads configuration from file, environment variables, and applies
// overrides, then validates the result.
func LoadConfig(configPath string, overrides map[string]string) (*Config, error) {
	cfg := DefaultConfig()

	// Load from config file if it exists
	if configPath != "" {
		if err := cfg.LoadFromFile(configPath); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Override with environment variables
	cfg.LoadFromEnv()

	// Override with command-line flags
	for key, value := range overrides {
		switch key {
		case "server_url":
			cfg.ServerURL = value
		case "enrollment_key":
			cfg.EnrollmentKey = value
		case "refresh_token_file":
			cfg.RefreshTokenFile = value
		case "report_interval":
			if d, err := time.ParseDuration(value); err == nil {
				cfg.ReportInterval = d
			}
		case "log_level":
			cfg.LogLevel = value
		case "log_file":
			cfg.LogFile = value
		case "insecure":
			cfg.Insecure = value == "true" || value == "1"
		case "ca_cert":
			cfg.CACert = value
		}
	}

	return cfg, cfg.Validate()
}

// LoadFromFile loads configuration from a YAML file
func (c *Config) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, c)
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	if val := os.Getenv("VULTRACK_SERVER_URL"); val != "" {
		c.ServerURL = val
	}
	if val := os.Getenv("VULTRACK_ENROLLMENT_KEY"); val != "" {
		c.EnrollmentKey = val
	}
	if val := os.Getenv("VULTRACK_REFRESH_TOKEN_FILE"); val != "" {
		c.RefreshTokenFile = val
	}
	if val := os.Getenv("VULTRACK_REPORT_INTERVAL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			c.ReportInterval = d
		}
	}
	if val := os.Getenv("VULTRACK_LOG_LEVEL"); val != "" {
		c.LogLevel = val
	}
	if val := os.Getenv("VULTRACK_LOG_FILE"); val != "" {
		c.LogFile = val
	}
	if val := os.Getenv("VULTRACK_INSECURE"); val != "" {
		c.Insecure = val == "true" || val == "1"
	}
	if val := os.Getenv("VULTRACK_CA_CERT"); val != "" {
		c.CACert = val
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	// Enforce HTTPS unless explicitly opted out with insecure=true.
	// Plain HTTP would transmit tokens and inventory data in cleartext.
	if !strings.HasPrefix(c.ServerURL, "https://") && !c.Insecure {
		return fmt.Errorf("server_url must use HTTPS (got %q); set insecure=true to allow HTTP", c.ServerURL)
	}
	if c.RefreshTokenFile == "" {
		return fmt.Errorf("refresh_token_file is required")
	}
	if c.ReportInterval <= 0 {
		return fmt.Errorf("report_interval must be positive")
	}
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		return fmt.Errorf("log_level must be one of: debug, info, warn, error")
	}
	return nil
}

// EnsureRefreshTokenDir ensures the directory for the refresh token file exists
// with restrictive permissions (0700) so only the service user can access it.
func (c *Config) EnsureRefreshTokenDir() error {
	dir := filepath.Dir(c.RefreshTokenFile)
	return os.MkdirAll(dir, 0700)
}
