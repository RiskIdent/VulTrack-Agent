package runtimefacts

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Service is a systemd service unit.
type Service struct {
	Unit          string `json:"unit"`
	ActiveState   string `json:"activeState"`
	SubState      string `json:"subState"`
	UnitFileState string `json:"unitFileState,omitempty"`
	Package       string `json:"package,omitempty"`
}

// showBatchSize is the maximum number of units per "systemctl show" call.
const showBatchSize = 100

func collectServices(ctx context.Context, e *env) collectorResult {
	out, err := e.run(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		if ctx.Err() != nil {
			return timeoutResult(categoryServices, ctx)
		}
		return errResult(categoryServices, commandError("systemctl list-units", err))
	}
	units := parseListUnits(string(out))

	idx, idxErr := e.dpkgIndex()
	var errs []CollectorError
	if idxErr != nil && e.packageManager == "dpkg" {
		errs = append(errs, CollectorError{Collector: categoryServices, Error: "package lookup unavailable: " + idxErr.Error()})
	}

	services := []Service{}
	seen := map[string]bool{}
	for start := 0; start < len(units); start += showBatchSize {
		end := min(start+showBatchSize, len(units))
		args := append([]string{"show", "--no-pager", "--property=Id,ActiveState,SubState,UnitFileState,FragmentPath"}, units[start:end]...)
		out, err := e.run(ctx, "systemctl", args...)
		if err != nil {
			if ctx.Err() != nil {
				return timeoutResult(categoryServices, ctx)
			}
			return errResult(categoryServices, commandError("systemctl show", err))
		}
		for _, props := range parseShow(string(out)) {
			id := props["Id"]
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			s := Service{
				Unit:          id,
				ActiveState:   props["ActiveState"],
				SubState:      props["SubState"],
				UnitFileState: props["UnitFileState"],
			}
			if idx != nil && props["FragmentPath"] != "" {
				s.Package, _ = idx.Lookup(props["FragmentPath"])
			}
			services = append(services, s)
		}
	}
	if ctx.Err() != nil {
		return timeoutResult(categoryServices, ctx)
	}

	sort.Slice(services, func(i, j int) bool { return services[i].Unit < services[j].Unit })
	var truncated []string
	if len(services) > maxServices {
		services = services[:maxServices]
		truncated = []string{categoryServices}
	}
	return collectorResult{
		apply:     func(r *Runtime) { r.Services = &services },
		errs:      errs,
		truncated: truncated,
	}
}

// parseListUnits returns the unit names (first column) of
// "systemctl list-units --no-legend --plain". A leading status marker
// ("●" or "*") of failed units is skipped.
func parseListUnits(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) == 0 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		units = append(units, f[0])
	}
	return units
}

// parseShow parses "systemctl show" output for several units: blocks of
// Key=Value lines separated by blank lines.
func parseShow(out string) []map[string]string {
	var blocks []map[string]string
	cur := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[k] = v
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	return blocks
}

// Virtualization collector -------------------------------------------------

func collectVirtualization(ctx context.Context, e *env) collectorResult {
	out, err := e.run(ctx, "systemd-detect-virt")
	v := strings.TrimSpace(string(out))
	if err != nil {
		// systemd-detect-virt prints "none" and exits non-zero on bare metal.
		var exitErr *exec.ExitError
		if v == "none" && (errors.As(err, &exitErr) || isExitStatus(err)) {
			return collectorResult{apply: func(r *Runtime) { r.Virtualization = "none" }}
		}
		if ctx.Err() != nil {
			return timeoutResult(categoryVirtualization, ctx)
		}
		return errResult(categoryVirtualization, commandError("systemd-detect-virt", err))
	}
	if v == "" || strings.ContainsAny(v, " \n") {
		return errResult(categoryVirtualization, "systemd-detect-virt: unexpected output")
	}
	return collectorResult{apply: func(r *Runtime) { r.Virtualization = v }}
}

// ExitStatusError is returned by test runners to simulate a command that ran
// and exited with a non-zero status.
type ExitStatusError struct{ Code int }

func (e *ExitStatusError) Error() string { return "exit status " + strconv.Itoa(e.Code) }

func isExitStatus(err error) bool {
	var es *ExitStatusError
	return errors.As(err, &es)
}

// commandError turns a command error into a short message.
func commandError(cmd string, err error) string {
	if errors.Is(err, exec.ErrNotFound) {
		return cmd + ": command not found"
	}
	return cmd + ": " + err.Error()
}
