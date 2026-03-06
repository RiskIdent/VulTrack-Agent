package collector

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// SystemInfo contains collected system information
type SystemInfo struct {
	Hostname       string
	OSFamily       string
	OSRelease      string
	OSCodename     string
	Kernel         string
	Arch           string
	IPv4Addrs      []string
	PackageManager string
}

// CollectSystemInfo collects system information from the host
func CollectSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{}

	// Hostname
	hostname, err := getHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	info.Hostname = hostname

	// OS information
	osFamily, osRelease, osCodename, err := getOSInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get OS info: %w", err)
	}
	info.OSFamily = osFamily
	info.OSRelease = osRelease
	info.OSCodename = osCodename

	// Kernel version
	kernel, err := getKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", err)
	}
	info.Kernel = kernel

	// Architecture
	arch, err := getArchitecture()
	if err != nil {
		return nil, fmt.Errorf("failed to get architecture: %w", err)
	}
	info.Arch = arch

	// IPv4 addresses
	ipv4Addrs, err := getIPv4Addresses()
	if err != nil {
		return nil, fmt.Errorf("failed to get IPv4 addresses: %w", err)
	}
	if len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found")
	}
	info.IPv4Addrs = ipv4Addrs

	// Package manager
	info.PackageManager = detectPackageManager()

	return info, nil
}

func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	// Attempt to resolve the FQDN via reverse DNS lookup (equivalent to hostname -f).
	// Falls back to the short hostname if DNS is unavailable or returns no results.
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return hostname, nil
	}
	fqdns, err := net.LookupAddr(addrs[0])
	if err != nil || len(fqdns) == 0 {
		return hostname, nil
	}
	// LookupAddr returns names with a trailing dot
	return strings.TrimSuffix(fqdns[0], "."), nil
}

func getOSInfo() (family, release, codename string, err error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", "", "", err
	}

	lines := strings.Split(string(data), "\n")
	var id, versionID, versionCodename string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_CODENAME=") {
			versionCodename = strings.Trim(strings.TrimPrefix(line, "VERSION_CODENAME="), "\"")
		}
	}

	// Normalize OS family
	family = normalizeOSFamily(id)
	if family == "" {
		return "", "", "", fmt.Errorf("unsupported OS: %s", id)
	}

	return family, versionID, versionCodename, nil
}

func normalizeOSFamily(id string) string {
	id = strings.ToLower(id)
	switch id {
	case "ubuntu", "debian":
		return id
	case "rhel", "centos", "rocky", "alma", "almalinux":
		if id == "almalinux" {
			return "alma"
		}
		return id
	default:
		// Check for variants
		if strings.Contains(id, "ubuntu") {
			return "ubuntu"
		}
		if strings.Contains(id, "debian") {
			return "debian"
		}
		if strings.Contains(id, "rhel") || strings.Contains(id, "redhat") {
			return "rhel"
		}
		if strings.Contains(id, "centos") {
			return "centos"
		}
		if strings.Contains(id, "rocky") {
			return "rocky"
		}
		if strings.Contains(id, "alma") {
			return "alma"
		}
		return ""
	}
}

func getKernelVersion() (string, error) {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getArchitecture() (string, error) {
	cmd := exec.Command("uname", "-m")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	arch := strings.TrimSpace(string(output))
	// Normalize architecture
	switch arch {
	case "x86_64":
		return "amd64", nil
	case "aarch64":
		return "arm64", nil
	case "i386", "i686":
		return "i386", nil
	default:
		return arch, nil
	}
}

func getIPv4Addresses() ([]string, error) {
	var addresses []string

	// Try 'ip -4 addr' first
	cmd := exec.Command("ip", "-4", "addr")
	output, err := cmd.Output()
	if err == nil {
		// Parse output: look for "inet " lines
		lines := strings.Split(string(output), "\n")
		inetRegex := regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+)`)
		for _, line := range lines {
			matches := inetRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				addr := matches[1]
				// Skip loopback if we have other addresses
				if addr != "127.0.0.1" {
					addresses = append(addresses, addr)
				}
			}
		}
		if len(addresses) > 0 {
			return addresses, nil
		}
	}

	// Fallback to 'hostname -I'
	cmd = exec.Command("hostname", "-I")
	output, err = cmd.Output()
	if err == nil {
		addrs := strings.Fields(string(output))
		for _, addr := range addrs {
			addr = strings.TrimSpace(addr)
			if addr != "" && addr != "127.0.0.1" {
				addresses = append(addresses, addr)
			}
		}
		if len(addresses) > 0 {
			return addresses, nil
		}
	}

	// Last resort: include loopback if nothing else found
	if len(addresses) == 0 {
		addresses = append(addresses, "127.0.0.1")
	}

	return addresses, nil
}

func detectPackageManager() string {
	// Check for dpkg (Debian/Ubuntu)
	if _, err := os.Stat("/usr/bin/dpkg"); err == nil {
		return "dpkg"
	}
	// Check for rpm (RHEL/CentOS)
	if _, err := os.Stat("/usr/bin/rpm"); err == nil {
		return "rpm"
	}
	return ""
}
