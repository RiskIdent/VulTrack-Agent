# VulTrack Agent

A lightweight system agent that collects server information and installed packages,
then reports them to a VulTrack vulnerability management server.

VulTrack Agent was **developed with AI assisted coding**. Be aware there might be dragons.

## Features

- **Static Binary**: No external runtime dependencies, easy deployment
- **Flexible Configuration**: Config file, environment variables, or command-line flags
- **Automatic Package Detection**: Supports dpkg (Debian/Ubuntu)
- **Robust Error Handling**: Retry logic with exponential backoff
- **Systemd Integration**: Pre-configured service for easy installation
- **Ansible Role**: Included Ansible role for automated fleet deployment

---

## Deployment with Ansible

An Ansible role is included at `ansible/roles/vultrack_agent/` for automated
installation, configuration, enrollment, and service management across a fleet
of servers.

For manual installation options, see [INSTALL.md](INSTALL.md).

### Requirements

- Ansible 2.12+
- Target hosts: Ubuntu with `systemd`

### Role Variables

```yaml
# Version to install
vultrack_agent_version: "1.0.0"

# Installation method: "deb" (recommended) or "binary"
vultrack_agent_install_method: "deb"

# VulTrack server URL — REQUIRED
vultrack_agent_server_url: ""

# Set to true to enroll the agent during the play
# When true, vultrack_agent_enrollment_key must also be set
vultrack_agent_enroll: false
vultrack_agent_enrollment_key: ""

# Agent configuration
vultrack_agent_token_file: "/etc/vultrack-agent/token"
vultrack_agent_report_interval: "1h"
vultrack_agent_log_level: "info"
vultrack_agent_log_file: ""
vultrack_agent_insecure: false
vultrack_agent_ca_cert: ""

# Systemd service management
vultrack_agent_service_state: "started"
vultrack_agent_service_enabled: true

# GitHub source (usually no need to change)
vultrack_agent_github_url: "https://github.com"
vultrack_agent_github_repo: "RiskIdent/VulTrack-Agent"

# Installation paths (usually no need to change)
vultrack_agent_bin_path: "/usr/local/bin/vultrack-agent"
vultrack_agent_config_dir: "/etc/vultrack-agent"
vultrack_agent_config_file: "/etc/vultrack-agent/config.yaml"
```

### Example Playbooks

#### Install and enroll in one play

```yaml
- name: Deploy VulTrack Agent
  hosts: all
  become: true
  roles:
    - role: vultrack_agent
      vars:
        vultrack_agent_version: "1.0.0"
        vultrack_agent_server_url: "https://vultrack.example.com"
        vultrack_agent_enroll: true
        vultrack_agent_enrollment_key: "{{ lookup('env', 'VULTRACK_ENROLLMENT_KEY') }}"
```

#### Install only (enroll separately)

```yaml
- name: Deploy VulTrack Agent
  hosts: all
  become: true
  roles:
    - role: vultrack_agent
      vars:
        vultrack_agent_version: "1.0.0"
        vultrack_agent_server_url: "https://vultrack.example.com"
```

#### Binary install method

```yaml
- name: Deploy VulTrack Agent (binary)
  hosts: all
  become: true
  roles:
    - role: vultrack_agent
      vars:
        vultrack_agent_version: "1.0.0"
        vultrack_agent_install_method: "binary"
        vultrack_agent_server_url: "https://vultrack.example.com"
```

### What the Role Does

1. Maps the system architecture (`aarch64` → `arm64`, others → `amd64`)
2. Validates required variables (`vultrack_agent_server_url`, and `vultrack_agent_enrollment_key` when enrolling)
3. Creates the system user and config directory (`/etc/vultrack-agent/`)
4. Downloads and installs the agent from GitHub Releases (`.deb` or binary)
5. Writes the configuration file from template
6. Optionally runs `vultrack-agent enroll` (skipped if token file already exists — idempotent)
7. Ensures the systemd service is enabled and running

---

## Configuration

Configuration is loaded from three sources in the following priority order
(highest to lowest):

1. **Command-line flags**
2. **Environment variables**
3. **Config file**

### Config File

Default location: `/etc/vultrack-agent/config.yaml`

A custom path can be specified with the global `--config` flag:

```bash
vultrack-agent --config /path/to/config.yaml report
```

Full reference:

```yaml
# VulTrack server URL (required)
server_url: https://vultrack.example.com

# Enrollment key for initial registration (can also be passed via flag)
enrollment_key: ""

# Path to store the agent token
token_file: /etc/vultrack-agent/token

# How often to send reports in daemon mode (default: 1h)
# Examples: 30m, 1h, 2h, 24h
report_interval: 1h

# Log level: debug, info, warn, error (default: info)
log_level: info

# Path to log file (empty = stdout/journald)
log_file: ""

# Skip TLS certificate verification — only use for testing!
insecure: false

# Path to a custom CA certificate in PEM format (optional)
ca_cert: ""
```

An annotated example is available at `contrib/config.yaml.example`.

### Environment Variables

| Variable | Description |
|---|---|
| `VULTRACK_SERVER_URL` | VulTrack server URL |
| `VULTRACK_ENROLLMENT_KEY` | Enrollment key |
| `VULTRACK_TOKEN_FILE` | Path to token file |
| `VULTRACK_REPORT_INTERVAL` | Report interval (e.g. `1h`, `30m`) |
| `VULTRACK_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) |
| `VULTRACK_LOG_FILE` | Path to log file |
| `VULTRACK_INSECURE` | Skip TLS verification (`true`/`false`) |
| `VULTRACK_CA_CERT` | Path to custom CA certificate |

### Command-Line Flags

| Flag | Description |
|---|---|
| `--config` | Path to config file |
| `--server-url` | VulTrack server URL |
| `--enrollment-key` | Enrollment key |
| `--token-file` | Path to token file |
| `--log-level` | Log level |
| `--log-file` | Path to log file |
| `--insecure` | Skip TLS verification |
| `--ca-cert` | Path to custom CA certificate |

---

## Usage

### Enroll Agent

Register the agent with the VulTrack server. Requires an enrollment key
obtained from the VulTrack web UI.

```bash
sudo vultrack-agent enroll --enrollment-key YOUR_ENROLLMENT_KEY
```

On success, the agent token is saved to the configured `token_file`.

### One-Time Report

```bash
sudo vultrack-agent report
```

### Daemon Mode

```bash
# Recommended: run as a systemd service
sudo systemctl start vultrack-agent

# Or run manually in the foreground
sudo vultrack-agent daemon
```

The daemon handles `SIGINT` and `SIGTERM` for graceful shutdown and sends an
initial report immediately on startup.

### Export Report (without Server)

Collect all data locally and write it as formatted JSON — without contacting
the server. Useful for debugging or offline inspection:

```bash
sudo vultrack-agent export -o report.json
sudo vultrack-agent export | jq .
```

### Check Status

Display the active configuration, token state, and validate the token against
the server:

```bash
sudo vultrack-agent status
```

---

## Collected Information

### System Information

| Field | Description | Example |
|---|---|---|
| `hostname` | FQDN of the system | `server01.example.com` |
| `osFamily` | OS family | `ubuntu`, `debian`, `rhel`, `centos`, `rocky`, `alma` |
| `osRelease` | OS version | `24.04`, `12`, `9.4` |
| `osCodename` | OS codename (if available) | `noble`, `bookworm` |
| `kernel` | Kernel version (`uname -r`) | `6.8.0-31-generic` |
| `arch` | System architecture | `amd64`, `arm64` |
| `ipv4Addrs` | Non-loopback IPv4 addresses | `["192.168.1.10"]` |
| `packageManager` | Detected package manager | `dpkg`, `rpm` |

### Package Information

For each installed package:

| Field | Description |
|---|---|
| `name` | Package name |
| `version` | Full version string |
| `arch` | Package architecture |
| `source` | Source package name |

Packages are collected via `dpkg-query` on Debian/Ubuntu systems and
`rpm -qa` on RHEL/CentOS/Rocky/Alma systems.

---

## Error Handling

| Condition | Behavior |
|---|---|
| Network error | Retry up to 3 times with exponential backoff (1s, 2s, 4s) |
| `401 Unauthorized` | Token invalid or expired — re-enrollment required, no retry |
| `403 Forbidden` | Agent pending approval or revoked — no retry |

---

## Security

- Token file is stored with `0600` permissions (root read-only)
- TLS certificate validation is enforced by default
- Custom CA certificates can be provided for internal PKI environments
- Tokens and enrollment keys are never fully written to logs
- The `status` command masks the token in output (shows first/last 4 characters only)
- Ansible tasks use `no_log: true` for steps that handle secrets

---

## Systemd Service

The systemd unit included in the package and in `contrib/vultrack-agent.service`
provides:

- Automatic restart on failure
- Network dependency (`network-online.target`)
- Security hardening (`NoNewPrivileges`, `PrivateTmp`, etc.)
- Logging to the systemd journal

### Viewing Logs

```bash
sudo journalctl -u vultrack-agent -f
sudo journalctl -u vultrack-agent -n 100
sudo journalctl -u vultrack-agent --since today
```

---

## Development

### Project Structure

```
vultrack-agent/
├── cmd/
│   └── vultrack-agent/
│       └── main.go              # CLI entry point (6 commands)
├── internal/
│   ├── api/
│   │   └── client.go            # HTTP client for VulTrack API
│   ├── collector/
│   │   ├── system.go            # System information collection
│   │   └── packages.go          # Package enumeration (dpkg/rpm)
│   └── config/
│       └── config.go            # Configuration loading and validation
├── ansible/
│   └── roles/
│       └── vultrack_agent/      # Ansible role
├── contrib/
│   ├── vultrack-agent.service   # Systemd unit file
│   └── config.yaml.example      # Annotated example configuration
├── .github/
│   ├── dependabot.yml           # Automated dependency updates
│   └── workflows/
│       ├── release.yml          # Automated release workflow
│       └── zizmor.yml           # GitHub Actions security scanning
├── build.sh                     # Multi-arch build script
├── INSTALL.md                   # Manual installation options
└── README.md
```

### Dependencies

- [`github.com/spf13/cobra`](https://github.com/spf13/cobra) — CLI framework
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — YAML parsing
- Standard library for everything else

### Build Requirements

- Go 1.21 or higher
- `dpkg-deb` for creating Debian packages (`apt install dpkg-dev`)

---

## License

MIT License
