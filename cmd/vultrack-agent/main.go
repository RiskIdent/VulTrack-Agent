package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vultrack/vultrack-agent/internal/api"
	"github.com/vultrack/vultrack-agent/internal/collector"
	"github.com/vultrack/vultrack-agent/internal/config"
	"github.com/vultrack/vultrack-agent/internal/runtimefacts"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "vultrack-agent",
	Short: "VulTrack Agent - Vulnerability management agent",
	Long:  "A lightweight system agent that collects server information and installed packages, then reports them to a VulTrack vulnerability management server.",
}

var configPath string
var flagOverrides = make(map[string]string)
var insecureFlag bool

// Flag variables
var flagServerURL string
var flagRefreshTokenFile string
var flagLogLevel string
var flagLogFile string
var flagCACert string

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "/etc/vultrack-agent/config.yaml", "Path to config file")
	rootCmd.PersistentFlags().StringVar(&flagServerURL, "server-url", "", "VulTrack server URL")
	rootCmd.PersistentFlags().StringVar(&flagRefreshTokenFile, "refresh-token-file", "", "Path to refresh token file")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&flagLogFile, "log-file", "", "Path to log file")
	rootCmd.PersistentFlags().BoolVar(&insecureFlag, "insecure", false, "Skip TLS certificate verification")
	rootCmd.PersistentFlags().StringVar(&flagCACert, "ca-cert", "", "Path to custom CA certificate")

	// Hook to populate flagOverrides after parsing
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if flagServerURL != "" {
			flagOverrides["server_url"] = flagServerURL
		}
		if flagRefreshTokenFile != "" {
			flagOverrides["refresh_token_file"] = flagRefreshTokenFile
		}
		if flagLogLevel != "" {
			flagOverrides["log_level"] = flagLogLevel
		}
		if flagLogFile != "" {
			flagOverrides["log_file"] = flagLogFile
		}
		if flagCACert != "" {
			flagOverrides["ca_cert"] = flagCACert
		}
		if insecureFlag {
			flagOverrides["insecure"] = "true"
		}
		return nil
	}

	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(versionCmd)
}

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll the agent with the VulTrack server",
	RunE:  runEnroll,
}

var enrollmentKeyFlag string
var forceEnrollFlag bool

func init() {
	enrollCmd.Flags().StringVar(&enrollmentKeyFlag, "enrollment-key", "", "Enrollment key for registration")
	enrollCmd.Flags().BoolVar(&forceEnrollFlag, "force", false, "Force re-enrollment, revoking any existing registration")
}

func runEnroll(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig(configPath, flagOverrides)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override enrollment key from flag if provided
	if enrollmentKeyFlag != "" {
		cfg.EnrollmentKey = enrollmentKeyFlag
	}

	if cfg.EnrollmentKey == "" {
		return fmt.Errorf("enrollment_key is required (use --enrollment-key flag or set in config)")
	}

	// Collect system info for hostname
	sysInfo, err := collector.CollectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}

	// Create API client
	client, err := api.NewClient(cfg.ServerURL, cfg.Insecure, cfg.CACert, cfg.EnrollmentKey, cfg.RefreshTokenFile)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	logInfo("Enrolling agent with hostname: %s", sysInfo.Hostname)
	resp, err := client.Enroll(sysInfo.Hostname, forceEnrollFlag)
	if err != nil {
		if apiErr, ok := err.(*api.APIError); ok {
			if apiErr.StatusCode == 401 {
				logError("Enrollment key is invalid, expired, or inactive.")
				return fmt.Errorf("enrollment failed: %w", err)
			}
			if apiErr.StatusCode == 409 {
				return fmt.Errorf("hostname %q is already registered; use --force to re-enroll", sysInfo.Hostname)
			}
		}
		if errors.Is(err, api.ErrAgentRevoked) {
			return fmt.Errorf("enrollment refused: this host's registration was revoked by an administrator; it must be removed on the server before the host can enroll again")
		}
		return fmt.Errorf("enrollment failed: %w", err)
	}

	if err := client.StoreTokens(resp.AccessToken, resp.ExpiresIn, resp.RefreshToken); err != nil {
		return fmt.Errorf("failed to save tokens: %w", err)
	}

	logInfo("Enrollment successful! Refresh token saved to %s", cfg.RefreshTokenFile)
	logInfo("Agent status: %s", resp.Status)
	if resp.Status == "pending" {
		logInfo("NOTE: The agent is pending admin approval. Reports will be sent once approved.")
	}
	return nil
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Send a one-time report to the server",
	RunE:  runReport,
}

func runReport(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig(configPath, flagOverrides)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Collect data
	logInfo("Collecting system information...")
	sysInfo, err := collector.CollectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}

	logInfo("Collecting installed packages...")
	packages, err := collector.CollectPackages(sysInfo.PackageManager)
	if err != nil {
		return fmt.Errorf("failed to collect packages: %w", err)
	}

	logInfo("Collected %d packages", len(packages))

	// Create API client
	client, err := api.NewClient(cfg.ServerURL, cfg.Insecure, cfg.CACert, cfg.EnrollmentKey, cfg.RefreshTokenFile)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Ensure we have a valid access token
	if err := client.EnsureValidToken(sysInfo.Hostname); err != nil {
		return fmt.Errorf("failed to obtain valid token: %w", err)
	}

	report, indexHash := prepareReport(cfg, sysInfo, packages, true)

	// Send report
	logInfo("Sending report to %s...", cfg.ServerURL)
	resp, err := submitReport(cfg, client, sysInfo.Hostname, report, indexHash)
	if err != nil {
		return fmt.Errorf("report failed: %w", err)
	}

	logInfo("Report sent successfully!")
	logInfo("Server ID: %d", resp.ServerID)
	logInfo("Package count: %d", resp.PackageCount)
	return nil
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export report data to a JSON file",
	Long:  "Collects system information and installed packages, then writes the report data as JSON to a file without sending it to the server.",
	RunE:  runExport,
}

var exportOutputFlag string

func init() {
	exportCmd.Flags().StringVarP(&exportOutputFlag, "output", "o", "", "Output file path (default: stdout)")
}

func runExport(cmd *cobra.Command, args []string) error {
	// Export works without a server configuration; the runtime settings fall
	// back to their defaults if the config cannot be loaded.
	cfg, err := config.LoadConfig(configPath, flagOverrides)
	if err != nil {
		logInfo("Config not usable (%v); using default runtime settings", err)
		cfg = config.DefaultConfig()
	}

	// Collect data
	logInfo("Collecting system information...")
	sysInfo, err := collector.CollectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}

	logInfo("Collecting installed packages...")
	packages, err := collector.CollectPackages(sysInfo.PackageManager)
	if err != nil {
		return fmt.Errorf("failed to collect packages: %w", err)
	}

	logInfo("Collected %d packages", len(packages))

	// The export always contains the full module index and never touches the
	// module index state file.
	report, _ := prepareReport(cfg, sysInfo, packages, false)

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	// Write to file or stdout
	if exportOutputFlag != "" {
		if err := os.WriteFile(exportOutputFlag, jsonData, 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		logInfo("Report exported to: %s", exportOutputFlag)
	} else {
		// Write to stdout
		fmt.Println(string(jsonData))
	}

	return nil
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run continuously, sending reports at configured interval",
	RunE:  runDaemon,
}

func runDaemon(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig(configPath, flagOverrides)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create API client
	client, err := api.NewClient(cfg.ServerURL, cfg.Insecure, cfg.CACert, cfg.EnrollmentKey, cfg.RefreshTokenFile)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	logInfo("Starting daemon mode (report interval: %v)", cfg.ReportInterval)
	logInfo("Press Ctrl+C to stop")

	// Send initial report
	if err := runReportCycle(cfg, client); err != nil {
		logCycleError("Initial report", err)
	}

	// Setup ticker
	ticker := time.NewTicker(cfg.ReportInterval)
	defer ticker.Stop()

	// Main loop
	for {
		select {
		case <-sigChan:
			logInfo("Received shutdown signal, stopping...")
			return nil
		case <-ticker.C:
			if err := runReportCycle(cfg, client); err != nil {
				logCycleError("Report", err)
			}
		}
	}
}

// runReportCycle runs one full report cycle: ensure valid token, collect, send.
func runReportCycle(cfg *config.Config, client *api.Client) error {
	// Collect system info first so we have the hostname for (re-)enrollment
	sysInfo, err := collector.CollectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}

	packages, err := collector.CollectPackages(sysInfo.PackageManager)
	if err != nil {
		return fmt.Errorf("failed to collect packages: %w", err)
	}

	// Ensure we have a valid access token (enroll / refresh / re-enroll as needed)
	if err := client.EnsureValidToken(sysInfo.Hostname); err != nil {
		return err
	}

	report, indexHash := prepareReport(cfg, sysInfo, packages, true)

	logInfo("Sending report (%d packages)...", len(packages))
	resp, err := submitReport(cfg, client, sysInfo.Hostname, report, indexHash)
	if err != nil {
		return err
	}

	logInfo("Report sent successfully (Server ID: %d, Packages: %d)", resp.ServerID, resp.PackageCount)
	return nil
}

// maxReportBytes keeps the request body well below the backend limit (4 MB).
const maxReportBytes = 3 << 20

// prepareReport builds the report request from the collected data and, if
// enabled, the runtime facts. useState applies the module index state file
// (send only the hash of an unchanged index). It returns the module index
// hash to store once the server has accepted the report ("" for none).
func prepareReport(cfg *config.Config, sysInfo *collector.SystemInfo, packages []collector.Package, useState bool) (*api.ReportRequest, string) {
	apiPackages := make([]api.Package, len(packages))
	for i, pkg := range packages {
		apiPackages[i] = api.Package{
			Name:    pkg.Name,
			Version: pkg.Version,
			Arch:    pkg.Arch,
			Source:  pkg.Source,
		}
	}

	report := &api.ReportRequest{
		Hostname:       sysInfo.Hostname,
		AgentVersion:   version,
		OSFamily:       sysInfo.OSFamily,
		OSRelease:      sysInfo.OSRelease,
		OSCodename:     sysInfo.OSCodename,
		Kernel:         sysInfo.Kernel,
		Arch:           sysInfo.Arch,
		PackageManager: sysInfo.PackageManager,
		IPv4Addrs:      sysInfo.IPv4Addrs,
		ReportedAt:     time.Now().UTC().Format(time.RFC3339),
		Packages:       apiPackages,
	}

	if !cfg.CollectRuntime {
		return report, ""
	}
	runtime, indexHash := collectRuntime(cfg, sysInfo.PackageManager, useState)
	if runtime == nil {
		return report, ""
	}
	report.Runtime = runtime

	// Without runtime the backend treats every category as unknown, which is
	// safe; an oversized body would be rejected as a whole.
	if body, err := json.Marshal(report); err != nil || len(body) > maxReportBytes {
		logError("Report would exceed %d bytes with runtime facts; sending it without them", maxReportBytes)
		report.Runtime = nil
		return report, ""
	}
	return report, indexHash
}

// collectRuntime collects and encodes the runtime facts. It never fails the
// report: on error it returns nil and the report goes out without them.
func collectRuntime(cfg *config.Config, packageManager string, useState bool) (json.RawMessage, string) {
	logInfo("Collecting runtime facts...")
	rt := runtimefacts.Collect(context.Background(), runtimefacts.Options{
		Collectors:     cfg.RuntimeCollectors,
		Timeout:        time.Duration(cfg.RuntimeTimeoutSeconds) * time.Second,
		PackageManager: packageManager,
	})
	if useState {
		runtimefacts.ApplyModuleIndexState(rt, cfg.ModuleIndexStateFile, time.Now())
	}
	data, err := rt.Encode()
	if err != nil {
		logError("Runtime facts omitted: %v", err)
		return nil, ""
	}
	for _, e := range rt.Errors {
		logInfo("Runtime facts: %s not collected: %s", e.Collector, e.Error)
	}
	return data, rt.FullModuleIndexHash()
}

// logCycleError logs why a report cycle did not send a report. Waiting for
// approval is expected and logged as information, not as an error.
func logCycleError(what string, err error) {
	switch {
	case errors.Is(err, api.ErrPendingApproval):
		logInfo("%s skipped: agent is pending admin approval; reports start once it is approved", what)
	case errors.Is(err, api.ErrAgentRevoked):
		logError("%s skipped: agent registration was revoked by an administrator; the agent will not re-enroll on its own", what)
	default:
		if apiErr, ok := err.(*api.APIError); ok && apiErr.StatusCode == 403 {
			logError("%s failed: access denied by the server (%v)", what, err)
			return
		}
		logError("%s failed: %v", what, err)
	}
}

// submitReport sends the report. If the server rejects the access token
// (e.g. after a backend restart), it forces a real token refresh and retries
// once. Only after the server accepted the report is the module index state
// file updated, so a failed report sends the full index again next time.
func submitReport(cfg *config.Config, client *api.Client, hostname string, report *api.ReportRequest, indexHash string) (*api.ReportResponse, error) {
	resp, err := client.Report(report)
	if apiErr, ok := err.(*api.APIError); ok && apiErr.StatusCode == 401 {
		client.InvalidateAccessToken()
		if rfErr := client.EnsureValidToken(hostname); rfErr != nil {
			return nil, fmt.Errorf("token refresh failed: %w", rfErr)
		}
		resp, err = client.Report(report)
	}
	if err != nil {
		return nil, err
	}
	if err := runtimefacts.SaveModuleIndexState(cfg.ModuleIndexStateFile, indexHash); err != nil {
		logError("%v", err)
	}
	return resp, nil
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current configuration and status",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig(configPath, flagOverrides)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	fmt.Println("=== VulTrack Agent Status ===")
	fmt.Printf("Server URL:          %s\n", cfg.ServerURL)
	fmt.Printf("Refresh Token File:  %s\n", cfg.RefreshTokenFile)
	fmt.Printf("Report Interval:     %v\n", cfg.ReportInterval)
	fmt.Printf("Log Level:           %s\n", cfg.LogLevel)
	fmt.Printf("Log File:            %s\n", cfg.LogFile)
	if cfg.EnrollmentKey != "" {
		fmt.Printf("Enrollment Key:      %s (set)\n", api.TokenPrefix(cfg.EnrollmentKey))
	} else {
		fmt.Printf("Enrollment Key:      (not set)\n")
	}

	// Check refresh token file
	if _, err := os.Stat(cfg.RefreshTokenFile); err == nil {
		fmt.Printf("Refresh Token:       present\n")
	} else {
		fmt.Printf("Refresh Token:       not found (agent not enrolled)\n")
		return nil
	}

	// Validate the token by running the state machine and sending a test report
	if cfg.EnrollmentKey == "" {
		fmt.Printf("Token Validation:    skipped (enrollment_key not set)\n")
		return nil
	}

	client, err := api.NewClient(cfg.ServerURL, cfg.Insecure, cfg.CACert, cfg.EnrollmentKey, cfg.RefreshTokenFile)
	if err != nil {
		fmt.Printf("Token Validation:    ERROR (could not create client: %v)\n", err)
		return nil
	}

	sysInfo, err := collector.CollectSystemInfo()
	if err != nil {
		fmt.Printf("Token Validation:    ERROR (could not collect system info: %v)\n", err)
		return nil
	}

	// A fresh process never holds an access token, so EnsureValidToken always
	// performs a real refresh against the server. The server validates the
	// refresh token (not revoked, not expired) and that the agent is active.
	// No report is sent: that would overwrite server data and trigger a scan.
	if err := client.EnsureValidToken(sysInfo.Hostname); err != nil {
		switch {
		case errors.Is(err, api.ErrPendingApproval):
			fmt.Printf("Token Validation:    PENDING (waiting for admin approval)\n")
		case errors.Is(err, api.ErrAgentRevoked):
			fmt.Printf("Token Validation:    REVOKED (registration revoked by an administrator)\n")
		default:
			fmt.Printf("Token Validation:    INVALID (%v)\n", err)
		}
		return nil
	}

	fmt.Printf("Token Validation:    VALID\n")
	return nil
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("vultrack-agent version %s (built %s)\n", version, buildTime)
	},
}

func logInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
