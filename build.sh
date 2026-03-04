#!/bin/bash
set -e

# Build script for VulTrack Agent
# Builds static binaries and optionally creates a Debian package

# Get version from git tag, fallback to dev
get_version() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$script_dir/scripts/get-version.sh" ]; then
        "$script_dir/scripts/get-version.sh"
    else
        # Fallback: inline version detection
        if ! git rev-parse --git-dir > /dev/null 2>&1; then
            echo "dev"
            return
        fi
        
        local git_version=$(git describe --tags --always --dirty 2>/dev/null)
        if [ -z "$git_version" ]; then
            echo "dev"
            return
        fi
        
        git_version=${git_version#v}
        if [[ $git_version == *-* ]]; then
            git_version=$(echo $git_version | cut -d'-' -f1)
        fi
        echo "$git_version"
    fi
}

VERSION="${VERSION:-$(get_version)}"
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ARCH="${ARCH:-amd64}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Build binary for a specific architecture
build_binary() {
    local arch=$1
    local output_name="vultrack-agent-${arch}"
    
    info "Building binary for ${arch}..."
    
    GOARCH="${arch}" GOOS=linux CGO_ENABLED=0 go build \
        -ldflags "-s -w -X 'main.version=${VERSION}' -X 'main.buildTime=${BUILD_TIME}'" \
        -o "${output_name}" \
        ./cmd/vultrack-agent
    
    info "Binary built: ${output_name}"
}

# Build all supported architectures
build_all() {
    info "Building binaries for all architectures..."
    build_binary amd64
    info "Build complete!"
}

# Create Debian package
build_deb() {
    local arch=$1
    local binary_name="vultrack-agent-${arch}"
    
    if [ ! -f "${binary_name}" ]; then
        error "Binary ${binary_name} not found. Building it first..."
        build_binary "${arch}"
    fi
    
    info "Creating Debian package for ${arch}..."
    
    # Create temporary directory structure
    local pkg_name="vultrack-agent_${VERSION}_${arch}"
    local pkg_dir="dist/${pkg_name}"
    
    mkdir -p "${pkg_dir}/DEBIAN"
    mkdir -p "${pkg_dir}/usr/local/bin"
    mkdir -p "${pkg_dir}/etc/vultrack-agent"
    mkdir -p "${pkg_dir}/etc/systemd/system"
    mkdir -p "${pkg_dir}/usr/lib/systemd/system"
    mkdir -p "${pkg_dir}/var/lib/vultrack-agent"
    
    # Copy binary
    cp "${binary_name}" "${pkg_dir}/usr/local/bin/vultrack-agent"
    chmod 755 "${pkg_dir}/usr/local/bin/vultrack-agent"
    
    # Copy systemd service
    cp contrib/vultrack-agent.service "${pkg_dir}/etc/systemd/system/vultrack-agent.service"
    
    # Copy example config
    cp contrib/config.yaml.example "${pkg_dir}/etc/vultrack-agent/config.yaml.example"
    
    # Create control file
    cat > "${pkg_dir}/DEBIAN/control" <<EOF
Package: vultrack-agent
Version: ${VERSION}
Architecture: ${arch}
Maintainer: VulTrack Team <support@vultrack.com>
Description: VulTrack Agent - Vulnerability management agent
 A lightweight system agent that collects server information and installed
 packages, then reports them to a VulTrack vulnerability management server.
Depends: systemd
EOF
    
    # Create postinst script
    cat > "${pkg_dir}/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

# Create dedicated system user if it doesn't exist
if ! id -u vultrack-agent > /dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "VulTrack Agent" vultrack-agent
fi

# Config directory: root owns, vultrack-agent group can read
chown root:vultrack-agent /etc/vultrack-agent
chmod 750 /etc/vultrack-agent

# Data directory: vultrack-agent owns (token written here by enroll)
chown vultrack-agent:vultrack-agent /var/lib/vultrack-agent
chmod 750 /var/lib/vultrack-agent

# Fix token file permissions if it exists
if [ -f /etc/vultrack-agent/token ]; then
    chown root:vultrack-agent /etc/vultrack-agent/token
    chmod 640 /etc/vultrack-agent/token
fi

# Config file: root owns, vultrack-agent group can read
if [ -f /etc/vultrack-agent/config.yaml ]; then
    chown root:vultrack-agent /etc/vultrack-agent/config.yaml
    chmod 640 /etc/vultrack-agent/config.yaml
fi

# Reload systemd
systemctl daemon-reload

# Enable service (but don't start - user needs to configure first)
# systemctl enable vultrack-agent.service

echo "VulTrack Agent installed successfully!"
echo ""
echo "Please configure /etc/vultrack-agent/config.yaml before starting the service."
POSTINST
    chmod 755 "${pkg_dir}/DEBIAN/postinst"
    
    # Create prerm script
    cat > "${pkg_dir}/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e

# Stop service before removal
systemctl stop vultrack-agent.service 2>/dev/null || true
systemctl disable vultrack-agent.service 2>/dev/null || true
PRERM
    chmod 755 "${pkg_dir}/DEBIAN/prerm"
    
    # Create postrm script
    cat > "${pkg_dir}/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e

# Reload systemd
systemctl daemon-reload
POSTRM
    chmod 755 "${pkg_dir}/DEBIAN/postrm"
    
    # Build package
    mkdir -p dist
    dpkg-deb --build "${pkg_dir}" "dist/${pkg_name}.deb"
    
    info "Debian package created: dist/${pkg_name}.deb"
}

# Main
case "${1:-all}" in
    binary)
        build_binary "${ARCH}"
        ;;
    all)
        build_all
        ;;
    deb)
        build_deb "${ARCH}"
        ;;
    *)
        echo "Usage: $0 {binary|all|deb}"
        echo ""
        echo "Commands:"
        echo "  binary  - Build binary for ARCH (default: amd64)"
        echo "  all     - Build binaries for all architectures"
        echo "  deb     - Build Debian package for ARCH (default: amd64)"
        echo ""
        echo "Environment variables:"
        echo "  VERSION - Version string (default: dev)"
        echo "  ARCH    - Architecture: amd64 (default: amd64)"
        exit 1
        ;;
esac
