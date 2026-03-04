# VulTrack Agent — Manual Installation

This document covers manual installation options. For automated fleet deployment,
see the [Ansible deployment section in the README](README.md#deployment-with-ansible).

---

## From GitHub Releases

Pre-built binaries and Debian packages are available on the
[Releases page](https://github.com/RiskIdent/VulTrack-Agent/releases).

### Debian Package (recommended)

```bash
VERSION=1.0.0
ARCH=amd64

curl -fsSL \
  -o /tmp/vultrack-agent_${VERSION}_${ARCH}.deb \
  "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/vultrack-agent_${VERSION}_${ARCH}.deb"

sudo dpkg -i /tmp/vultrack-agent_${VERSION}_${ARCH}.deb
rm /tmp/vultrack-agent_${VERSION}_${ARCH}.deb
```

The Debian package installs:
- Binary at `/usr/local/bin/vultrack-agent`
- Example config at `/etc/vultrack-agent/config.yaml.example`
- Systemd service at `/etc/systemd/system/vultrack-agent.service`
- Data directory at `/var/lib/vultrack-agent/`

### Static Binary

For non-Debian systems or when a minimal install is preferred:

```bash
VERSION=1.0.0
ARCH=amd64

sudo curl -fsSL \
  -o /usr/local/bin/vultrack-agent \
  "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/vultrack-agent-${ARCH}"

sudo chmod 755 /usr/local/bin/vultrack-agent
```

Then deploy the systemd service manually:

```bash
sudo curl -fsSL \
  -o /etc/systemd/system/vultrack-agent.service \
  "https://github.com/RiskIdent/VulTrack-Agent/releases/download/v${VERSION}/vultrack-agent.service"

sudo systemctl daemon-reload
```

---

## Building from Source

```bash
git clone https://github.com/RiskIdent/VulTrack-Agent.git
cd VulTrack-Agent

go mod download

# Build binary for current architecture
./build.sh binary

# Build for all architectures (amd64 + arm64)
./build.sh all

# Create a Debian package
./build.sh deb

# Override version manually
VERSION=1.0.0 ./build.sh deb
```

**Versioning:** The build script derives the version from the current Git tag.
If no tag is present, it falls back to `dev`.

```bash
git tag v1.0.0
./build.sh binary   # produces vultrack-agent-amd64 with version 1.0.0
```

### Requirements

- Go 1.21 or higher
- `dpkg-deb` for Debian packages (`apt install dpkg-dev`)

### Creating Releases

Pushing a version tag triggers the GitHub Actions workflow, which automatically:
- Builds the binary for amd64
- Creates a Debian package for amd64
- Publishes a GitHub Release with all assets and a SHA256SUMS file

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Post-Installation Setup

Regardless of installation method, the initial setup is identical:

### 1. Configure

```bash
sudo cp /etc/vultrack-agent/config.yaml.example /etc/vultrack-agent/config.yaml
sudo nano /etc/vultrack-agent/config.yaml
```

Set at minimum:

```yaml
server_url: https://vultrack.example.com
```

### 2. Enroll

```bash
sudo vultrack-agent enroll --enrollment-key YOUR_ENROLLMENT_KEY
```

The agent token is saved to `/etc/vultrack-agent/token` (permissions: `0600`).

### 3. Start the Service

```bash
sudo systemctl enable --now vultrack-agent
sudo systemctl status vultrack-agent
```
