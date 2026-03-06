package collector

import (
	"fmt"
	"os/exec"
	"strings"
)

// Package represents an installed package
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Source  string `json:"source"`
}

// CollectPackages collects installed packages based on the package manager
func CollectPackages(packageManager string) ([]Package, error) {
	switch packageManager {
	case "dpkg":
		return collectDPKGPackages()
	case "rpm":
		return collectRPMPackages()
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", packageManager)
	}
}

func collectDPKGPackages() ([]Package, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${source:Package}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query dpkg packages: %w", err)
	}
	return parseDPKGOutput(string(output)), nil
}

func parseDPKGOutput(output string) []Package {
	var packages []Package
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		pkg := Package{
			Name:    fields[0],
			Version: fields[1],
			Arch:    fields[2],
		}
		if len(fields) > 3 && fields[3] != "" {
			pkg.Source = fields[3]
		} else {
			pkg.Source = pkg.Name
		}
		packages = append(packages, pkg)
	}
	return packages
}

func collectRPMPackages() ([]Package, error) {
	// Use %{SOURCENAME} instead of %{SOURCERPM} to get the source package name
	// directly without fragile string parsing of "name-version-release.src.rpm".
	cmd := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{EVR}\t%{ARCH}\t%{SOURCENAME}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query rpm packages: %w", err)
	}
	return parseRPMOutput(string(output)), nil
}

func parseRPMOutput(output string) []Package {
	var packages []Package
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		pkg := Package{
			Name:    fields[0],
			Version: fields[1],
			Arch:    fields[2],
		}
		if len(fields) > 3 && fields[3] != "" && fields[3] != "(none)" {
			pkg.Source = fields[3]
		} else {
			pkg.Source = pkg.Name
		}
		packages = append(packages, pkg)
	}
	return packages
}
