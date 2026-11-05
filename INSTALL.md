# VulTrack Agent — Manual Installation

This document covers manual installation options. For automated fleet deployment,
see the [Ansible deployment section in the README](README.md#deployment-with-ansible).

Releases contain artifacts for **Linux amd64** only. See
[Supported Platforms](README.md#supported-platforms).

---

## From GitHub Releases

Pre-built binaries and Debian packages are available on the
[Releases page](https://github.com/RiskIdent/VulTrack-Agent/releases), together
with a `SHA256SUMS` file.

### Debian Package (recommended)

```bash
VERSION=1.2.1

curl -fsSLO "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/vultrack-agent_${VERSION}_amd64.deb"
curl -fsSLO "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS

sudo dpkg -i vultrack-agent_${VERSION}_amd64.deb
```

The Debian package:
- installs the binary at `/usr/local/bin/vultrack-agent`
- installs an example config at `/etc/vultrack-agent/config.yaml.example`
- installs the systemd service at `/etc/systemd/system/vultrack-agent.service`
- creates the system user `vultrack-agent` and the data directory
  `/var/lib/vultrack-agent/` (owned by that user)
- does **not** enable or start the service

### Static Binary

For non-Debian systems or when a minimal install is preferred. These steps do
what the Debian package does:

```bash
VERSION=1.2.1
RAW="https://raw.githubusercontent.com/RiskIdent/VulTrack-Agent/v${VERSION}"

# Binary (verify the checksum)
curl -fsSLO "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/vultrack-agent-amd64"
curl -fsSLO "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
sudo install -m 755 vultrack-agent-amd64 /usr/local/bin/vultrack-agent

# Service user and directories
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --comment "VulTrack Agent" vultrack-agent
sudo install -d -o root -g vultrack-agent -m 750 /etc/vultrack-agent
sudo install -d -o vultrack-agent -g vultrack-agent -m 750 /var/lib/vultrack-agent

# Example config and systemd unit (not release assets; taken from the tagged source)
sudo curl -fsSL -o /etc/vultrack-agent/config.yaml.example "${RAW}/contrib/config.yaml.example"
sudo curl -fsSL -o /etc/systemd/system/vultrack-agent.service "${RAW}/contrib/vultrack-agent.service"
sudo systemctl daemon-reload
```

On RPM-based systems the agent reports packages via `rpm`; runtime facts that
need dpkg (package attribution, `packageInfo`, installed kernels, reboot
required) are reported as unknown.

---

## Post-Installation Setup

Regardless of installation method, the initial setup is identical.

### 1. Configure

```bash
sudo install -o root -g vultrack-agent -m 640 \
  /etc/vultrack-agent/config.yaml.example /etc/vultrack-agent/config.yaml
sudo nano /etc/vultrack-agent/config.yaml
```

The config contains the enrollment key, so it must not be world-readable
(`640`, group `vultrack-agent`). Set at minimum:

```yaml
server_url: https://vultrack.example.com
enrollment_key: YOUR_ENROLLMENT_KEY   # keep it: needed for automatic re-enrollment
```

### 2. Enroll

Run the command as the service user, so the refresh token file belongs to it:

```bash
sudo -u vultrack-agent vultrack-agent enroll
```

The refresh token is saved to `/var/lib/vultrack-agent/refresh.token`
(permissions `0600`). The access token is held in memory only.

If you enrolled as root by mistake, fix the owner:

```bash
sudo chown vultrack-agent:vultrack-agent /var/lib/vultrack-agent/refresh.token
```

### 3. Start the Service

```bash
sudo systemctl enable --now vultrack-agent
sudo systemctl status vultrack-agent
sudo journalctl -u vultrack-agent -n 20
```

---

## Upgrading

Install the new package or binary the same way. Then make sure the service is
enabled and running again:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vultrack-agent
sudo systemctl restart vultrack-agent
```

The pre-removal script of the Debian packages up to and including 1.2.1 stops
**and disables** the service on every upgrade, so without this step the agent
stays stopped.

---

## Building from Source

```bash
git clone https://github.com/RiskIdent/VulTrack-Agent.git
cd VulTrack-Agent

go mod download

# Static binary for ARCH (default: amd64) → vultrack-agent-amd64
./build.sh binary

# Currently the same as "binary" for amd64 (only amd64 is built)
./build.sh all

# Debian package for ARCH (default: amd64) → dist/vultrack-agent_<version>_amd64.deb
./build.sh deb

# Other architectures are not released, but can be built
ARCH=arm64 ./build.sh binary

# Override the version
VERSION=1.2.1 ./build.sh deb
```

**Versioning:** The build script derives the version from `git describe`: the
nearest tag without the leading `v` (commits after the tag are ignored, so a
build after `v1.2.1` is still `1.2.1`). Without any tag the abbreviated commit
hash is used, outside a Git checkout `dev`. Set `VERSION` to override it.

### Requirements

- Go 1.26 or higher
- `dpkg-deb` for Debian packages (`apt install dpkg-dev`)

### Creating Releases

Pushing a version tag triggers the GitHub Actions workflow, which:
- builds the static binary for amd64
- builds the Debian package for amd64
- publishes a GitHub Release with both and a `SHA256SUMS` file

```bash
git tag -a v1.2.1 -m "v1.2.1"
git push origin v1.2.1
```
