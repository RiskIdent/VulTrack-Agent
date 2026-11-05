# VulTrack Agent

A lightweight system agent that collects server information and installed packages,
then reports them to a VulTrack vulnerability management server.

VulTrack Agent was **developed with AI assisted coding**. Be aware there might be dragons.

The VulTrack Server can be found in [this repository](https://github.com/RiskIdent/VulTrack).

## Features

- **Static Binary**: No external runtime dependencies, easy deployment
- **Flexible Configuration**: Config file, environment variables, or command-line flags
- **Automatic Package Detection**: Supports dpkg (Debian/Ubuntu)
- **Robust Error Handling**: Retry logic with exponential backoff
- **Runtime Facts**: Loaded kernel modules, listening sockets, packages in use, services and kernel settings let the server rule out vulnerabilities that cannot affect the host
- **Automatic Token Refresh**: Short-lived access tokens are refreshed automatically; the agent re-enrolls itself when the refresh token expires
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
# IMPORTANT: enrollment_key must remain in the config permanently.
# The agent needs it to re-enroll automatically when the refresh token
# expires or is revoked.
vultrack_agent_enrollment_key: ""

# Agent configuration
vultrack_agent_refresh_token_file: "/var/lib/vultrack-agent/refresh.token"
vultrack_agent_report_interval: "1h"
vultrack_agent_log_level: "info"
vultrack_agent_log_file: ""
vultrack_agent_insecure: false
vultrack_agent_ca_cert: ""

# Runtime facts (see "Runtime Facts" below)
vultrack_agent_collect_runtime: true
vultrack_agent_runtime_collectors: [kernel, listeners, packages_in_use, services, virtualization]
vultrack_agent_runtime_timeout_seconds: 20
vultrack_agent_module_index_state_file: "/var/lib/vultrack-agent/module-index.sha256"

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
6. Optionally runs `vultrack-agent enroll` (skipped if refresh token file already exists — idempotent)
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

# Enrollment key (required — keep this permanently in the config).
# Used for initial enrollment and for automatic re-enrollment when the
# refresh token expires or is revoked.
enrollment_key: ""

# Path to persist the refresh token on disk.
# The access token is held in memory only and is never written to disk.
refresh_token_file: /var/lib/vultrack-agent/refresh.token

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

# Runtime facts (see "Runtime Facts")
# Master switch; false omits the runtime facts entirely (default: true)
collect_runtime: true
# Collectors to run (default: all)
runtime_collectors: [kernel, listeners, packages_in_use, services, virtualization]
# Overall time budget for all collectors in seconds (default: 20)
runtime_timeout_seconds: 20
# Hash of the last kernel module index the server accepted
module_index_state_file: /var/lib/vultrack-agent/module-index.sha256
```

An annotated example is available at `contrib/config.yaml.example`.

### Environment Variables

| Variable | Description |
|---|---|
| `VULTRACK_SERVER_URL` | VulTrack server URL |
| `VULTRACK_ENROLLMENT_KEY` | Enrollment key (keep permanently) |
| `VULTRACK_REFRESH_TOKEN_FILE` | Path to refresh token file |
| `VULTRACK_REPORT_INTERVAL` | Report interval (e.g. `1h`, `30m`) |
| `VULTRACK_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) |
| `VULTRACK_LOG_FILE` | Path to log file |
| `VULTRACK_INSECURE` | Skip TLS verification (`true`/`false`) |
| `VULTRACK_CA_CERT` | Path to custom CA certificate |
| `VULTRACK_COLLECT_RUNTIME` | Collect runtime facts (`true`/`false`) |
| `VULTRACK_RUNTIME_COLLECTORS` | Comma-separated list of collectors (e.g. `kernel,services`) |
| `VULTRACK_RUNTIME_TIMEOUT_SECONDS` | Time budget for all collectors in seconds |
| `VULTRACK_MODULE_INDEX_STATE_FILE` | Path to the module index state file |

### Command-Line Flags

| Flag | Description |
|---|---|
| `--config` | Path to config file |
| `--server-url` | VulTrack server URL |
| `--enrollment-key` | Enrollment key |
| `--refresh-token-file` | Path to refresh token file |
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

On success, the refresh token is saved to `refresh_token_file`. The access
token is held in memory only.

To force re-enrollment (revokes the existing registration):

```bash
sudo vultrack-agent enroll --enrollment-key YOUR_ENROLLMENT_KEY --force
```

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
initial report immediately on startup. It automatically refreshes the access
token and re-enrolls using `enrollment_key` when the refresh token expires.

### Export Report (without Server)

Collect all data locally and write it as formatted JSON — without contacting
the server. Useful for debugging or offline inspection:

```bash
sudo vultrack-agent export -o report.json
sudo vultrack-agent export | jq .
sudo vultrack-agent export | jq .runtime
```

The export contains the runtime facts (always with the full kernel module
index) and does not touch the module index state file. If no usable config
file exists, the default runtime settings are used.

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

### Runtime Facts

Every report also carries an optional `runtime` object. The server uses it to
decide automatically whether a vulnerability can affect the host, for example
"this kernel CVE is in a module that is not loaded and cannot be loaded" or
"this daemon only listens on 127.0.0.1".

| Collector (`runtime_collectors`) | Field | Content | Source |
|---|---|---|---|
| `kernel` | `kernel` | Kernel release, `modulesDisabled`, loaded modules (with path), modules blacklisted or disabled in `modprobe.d`, the kernel module index, selected sysctls, installed kernels, reboot required | `/proc`, `/lib/modules/<release>`, `modprobe.d`, `/var/lib/dpkg/status`, `/var/run/reboot-required*` |
| `listeners` | `listeners` | Listening TCP and bound UDP sockets, also inside containers, with process name, executable, package and systemd unit | `/proc/net/*`, `/proc/<pid>/{fd,comm,exe,cgroup,ns/net}` |
| `packages_in_use` | `packagesInUse` | Packages whose files are mapped by running processes, and processes still running a replaced (upgraded) file | `/proc/<pid>/{maps,exe,comm}` |
| `services` | `services` | All systemd service units with active, sub and unit file state and package | `systemctl list-units`, `systemctl show` |
| `virtualization` | `virtualization` | Virtualization or container type | `systemd-detect-virt` |

Packages are resolved with the dpkg file lists (`/var/lib/dpkg/info/*.list`),
including merged `/usr` and dpkg diversions. On non-dpkg systems the package
fields, `installedKernels`, `rebootRequired` and `packagesInUse` are omitted.
Processes with their own root filesystem (containers) are reported with
process, executable and unit, but never with a host package, and they do not
count in `packagesInUse`: their paths belong to the container image, not to the
host's dpkg database. With socket activation (e.g. `ssh.socket`) the listener
is attributed to the service that inherited the socket, not to systemd.

**Unknown is not empty.** A collector that cannot run (missing permission,
missing tool, error, timeout) is omitted and the reason is listed in
`runtime.errors`. An empty list means "collected, nothing found". Values that
cannot be determined exactly (e.g. the package of a file) are left out instead
of guessed. Collection problems never prevent the report from being sent.

**Not collected:** command lines, environment variables, working directories,
open files other than mapped executables and libraries, user names or UIDs of
processes, and the contents of configuration files other than the `blacklist`
and `install` directives in `modprobe.d`.

**Privileges.** `listeners` and `packages_in_use` need to read other
processes' `/proc` entries. The agent checks for `CAP_DAC_READ_SEARCH` and
`CAP_SYS_PTRACE` (root has both; the systemd unit grants them to the service
user). Without them both collectors are reported as `insufficient privileges`,
because partial data would look complete.

**Size and performance.** All collectors share the time budget
`runtime_timeout_seconds`. Lists are capped (2,000 listeners, 3,000 packages
in use, 2,000 services, 20 processes per package); a capped category is listed
in `runtime.truncated`. The `runtime` object stays below 1 MB. The kernel
module index (several thousand lines) is sent in full only when it changed,
when the server has not yet accepted it, or once every 24 hours; otherwise only
its hash is sent. The hash of the accepted index is stored in
`module_index_state_file`, the only file runtime collection writes.

**Example.** Abbreviated `runtime` object from an Ubuntu 24.04 VM running
Docker (agent 1.2.1; container names and IDs anonymised, most list entries
removed). The module index is shown in its hash-only form, as sent when the
server already has it:

```json
{
  "schemaVersion": 1,
  "collectedAt": "2026-11-05T11:48:58Z",
  "kernel": {
    "release": "6.8.0-147-generic",
    "modulesDisabled": false,
    "loadedModules": [
      {"name": "nf_tables", "path": "kernel/net/netfilter/nf_tables.ko.zst"},
      {"name": "overlay", "path": "kernel/fs/overlayfs/overlay.ko.zst"},
      {"name": "tls", "path": "kernel/net/tls/tls.ko.zst"}
    ],
    "blacklistedModules": [
      {"name": "algif_aead", "installCommand": "/bin/false"},
      {"name": "pcspkr"}
    ],
    "moduleIndex": {"hash": "sha256:a950e3bc590c79f416d2cd92bca51a48c8adec323ad49d585f22dc69411ff160"},
    "sysctls": {
      "kernel.apparmor_restrict_unprivileged_userns": "1",
      "kernel.dmesg_restrict": "1",
      "kernel.kptr_restrict": "1",
      "kernel.modules_disabled": "0",
      "kernel.perf_event_paranoid": "4",
      "kernel.unprivileged_bpf_disabled": "2",
      "kernel.unprivileged_userns_clone": "1",
      "kernel.yama.ptrace_scope": "1",
      "user.max_user_namespaces": "47691"
    },
    "installedKernels": ["6.8.0-137-generic", "6.8.0-147-generic"],
    "rebootRequired": false
  },
  "listeners": [
    {"protocol": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd", "exe": "/usr/sbin/sshd",
     "package": "openssh-server", "unit": "ssh.service", "hostNetns": true},
    {"protocol": "tcp", "address": "0.0.0.0", "port": 8080, "process": "docker-proxy", "exe": "/usr/bin/docker-proxy",
     "package": "docker-ce", "unit": "docker.service", "hostNetns": true},
    {"protocol": "tcp", "address": "127.0.0.53", "port": 53, "process": "systemd-resolve", "exe": "/usr/lib/systemd/systemd-resolved",
     "package": "systemd-resolved", "unit": "systemd-resolved.service", "hostNetns": true},
    {"protocol": "tcp6", "address": "::", "port": 443, "process": "caddy", "exe": "/usr/bin/caddy",
     "unit": "docker-4d88e05acf61.scope", "hostNetns": true},
    {"protocol": "tcp6", "address": "::", "port": 8080, "process": "app", "exe": "/app/app",
     "unit": "docker-20984cf3b843.scope", "hostNetns": false},
    {"protocol": "udp", "address": "0.0.0.0", "port": 123, "process": "chronyd", "exe": "/usr/sbin/chronyd",
     "package": "chrony", "unit": "chrony.service", "hostNetns": true}
  ],
  "packagesInUse": [
    {"package": "docker-ce", "processes": ["docker-proxy", "dockerd"]},
    {"package": "libssl3t64", "processes": ["clamd", "freshclam", "fwupd", "sshd", "sudo", "systemd", "systemd-resolve"]},
    {"package": "openssh-server", "processes": ["sshd"]}
  ],
  "services": [
    {"unit": "docker.service", "activeState": "active", "subState": "running", "unitFileState": "enabled", "package": "docker-ce"},
    {"unit": "node_exporter.service", "activeState": "active", "subState": "running", "unitFileState": "enabled"},
    {"unit": "ssh.service", "activeState": "active", "subState": "running", "unitFileState": "enabled", "package": "openssh-server"}
  ],
  "virtualization": "kvm",
  "truncated": ["packagesInUse"]
}
```

What the example shows:

- `sshd` owns port 22 although `ssh.socket` (PID 1) holds the socket as well.
- `caddy` runs in a container with host networking (`hostNetns: true`), `app`
  in its own network namespace; neither gets a host package.
- `node_exporter` was installed outside dpkg, so it has no `package`.
- `truncated` lists `packagesInUse` because `libc6` is used by more than 20
  distinct processes on this host.

**Disabling.** Set `collect_runtime: false` (or `VULTRACK_COLLECT_RUNTIME=false`)
to omit the runtime facts entirely, or list only the wanted collectors in
`runtime_collectors`. The server then treats the missing facts as unknown and
never dismisses a finding based on them.

---

## Token Lifecycle

The agent uses two tokens:

| Token | Storage | Lifetime |
|---|---|---|
| **Access token** (JWT) | Memory only, never written to disk | Short-lived (default 24 h) |
| **Refresh token** (`rt_…`) | `refresh_token_file` (0600) | Long-lived (default 90 days) |

The agent manages token renewal automatically:

1. If a valid access token is in memory — use it directly.
2. If the access token is absent or expired — exchange the refresh token for a new pair.
3. If the refresh token is rejected (401) — re-enroll automatically using `enrollment_key`.
4. After enrollment, if the agent status is `pending` — wait for admin approval before reporting.

This is why **`enrollment_key` must remain permanently in the config** — it enables
fully autonomous recovery without manual intervention.

---

## Error Handling

| Condition | Behavior |
|---|---|
| Network error | Retry up to 3 times with exponential backoff (1s, 2s, 4s) |
| `401` on report | Refresh access token and retry once |
| `401` on token refresh | Re-enroll with `force=true` using `enrollment_key` |
| `401` on enrollment | Enrollment key invalid — log error and exit |
| `403 Forbidden` | Agent pending approval or revoked — no retry |
| `409 Conflict` on enroll | Hostname already registered — use `--force` to re-enroll |

---

## Security

- Refresh token file is stored with `0600` permissions (owner read-only)
- Refresh token directory is created with `0700` permissions
- Access token is held in memory only and never written to disk
- Token writes use an atomic write-then-rename pattern to prevent corruption
- TLS certificate validation is enforced by default
- Custom CA certificates can be provided for internal PKI environments
- Tokens and enrollment keys are never fully written to logs (only first 8 characters)
- Ansible tasks use `no_log: true` for steps that handle secrets
- The service runs as the unprivileged `vultrack-agent` user with only
  `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` (for runtime facts); the
  syscalls `ptrace`, `process_vm_readv`, `process_vm_writev` and
  `pidfd_getfd` are blocked, so the capabilities cannot be used to access
  other processes' memory

---

## Systemd Service

The systemd unit included in the package and in `contrib/vultrack-agent.service`
provides:

- Automatic restart on failure
- Network dependency (`network-online.target`)
- Security hardening (`NoNewPrivileges`, `PrivateTmp`, syscall filter, etc.)
- The capabilities needed for runtime facts (`CAP_DAC_READ_SEARCH`,
  `CAP_SYS_PTRACE`) and `AF_UNIX` for `systemctl`
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
│   │   └── client.go            # HTTP client for VulTrack API v2
│   ├── collector/
│   │   ├── system.go            # System information collection
│   │   └── packages.go          # Package enumeration (dpkg/rpm)
│   ├── runtimefacts/            # Runtime facts (kernel, listeners, packages
│   │   │                        #   in use, services, virtualization)
│   │   └── testdata/            # Fixture root filesystem and golden file
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
- [`go.yaml.in/yaml/v4`](https://pkg.go.dev/go.yaml.in/yaml/v4) — YAML parsing
- Standard library for everything else

### Build Requirements

- Go 1.26 or higher
- `dpkg-deb` for creating Debian packages (`apt install dpkg-dev`)

---

## License

MIT License
