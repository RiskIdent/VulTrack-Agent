// Package runtimefacts collects runtime facts about the host (kernel modules,
// listening sockets, packages in use, systemd services, virtualization) for
// the optional "runtime" object of the agent report.
//
// The backend uses these facts to dismiss vulnerability findings
// automatically, so two rules apply throughout:
//
//  1. Unknown is not empty. A category that cannot be collected is omitted
//     and the reason is recorded in Errors. An empty list is sent only when
//     the collector ran successfully and found nothing.
//  2. Never guess. A single value that cannot be determined exactly is left
//     out instead of being filled with a plausible value.
package runtimefacts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is the version of the runtime object produced by this package.
const SchemaVersion = 1

// Collector names, as used in the runtime_collectors configuration key.
const (
	CollectorKernel         = "kernel"
	CollectorListeners      = "listeners"
	CollectorPackagesInUse  = "packages_in_use"
	CollectorServices       = "services"
	CollectorVirtualization = "virtualization"
)

// AllCollectors lists every collector in the order their results are applied.
var AllCollectors = []string{
	CollectorKernel,
	CollectorListeners,
	CollectorPackagesInUse,
	CollectorServices,
	CollectorVirtualization,
}

// Category names as they appear in the runtime object (errors, truncated).
const (
	categoryKernel         = "kernel"
	categoryListeners      = "listeners"
	categoryPackagesInUse  = "packagesInUse"
	categoryServices       = "services"
	categoryVirtualization = "virtualization"
)

// categoryOf maps a collector name to its category name in the JSON object.
var categoryOf = map[string]string{
	CollectorKernel:         categoryKernel,
	CollectorListeners:      categoryListeners,
	CollectorPackagesInUse:  categoryPackagesInUse,
	CollectorServices:       categoryServices,
	CollectorVirtualization: categoryVirtualization,
}

// Size limits (see the specification, §5). Variables so tests can lower them.
var (
	maxRuntimeBytes     = 1 << 20
	maxListeners        = 2000
	maxPackagesInUse    = 3000
	maxServices         = 2000
	maxProcessesPerPkg  = 20
	errInsufficientPriv = "insufficient privileges"
)

// Runtime is the "runtime" object of the agent report.
//
// Categories are pointers: nil means "unknown" and is omitted from the JSON,
// a non-nil pointer to an empty slice is sent as [] and means "collected,
// nothing found".
type Runtime struct {
	SchemaVersion  int              `json:"schemaVersion"`
	CollectedAt    string           `json:"collectedAt"`
	Kernel         *Kernel          `json:"kernel,omitempty"`
	Listeners      *[]Listener      `json:"listeners,omitempty"`
	PackagesInUse  *[]PackageInUse  `json:"packagesInUse,omitempty"`
	Services       *[]Service       `json:"services,omitempty"`
	Virtualization string           `json:"virtualization,omitempty"`
	Errors         []CollectorError `json:"errors,omitempty"`
	Truncated      []string         `json:"truncated,omitempty"`
}

// CollectorError records why a collector (or part of it) produced no data.
type CollectorError struct {
	Collector string `json:"collector"`
	Error     string `json:"error"`
}

// CommandRunner runs an external command and returns its standard output.
// On failure it returns the output collected so far together with the error.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Options configures a collection run.
type Options struct {
	// Root is the directory that stands in for "/" (default "/"). Tests point
	// it at a fixture tree.
	Root string
	// Collectors to run; nil means all.
	Collectors []string
	// Timeout is the overall time budget for all collectors.
	Timeout time.Duration
	// PackageManager as detected by the system collector ("dpkg", "rpm", "").
	PackageManager string
	// Run executes external commands (systemctl, systemd-detect-virt).
	Run CommandRunner
	// Privileged reports whether the agent may read other processes' /proc
	// entries. Defaults to a check of the agent's effective capabilities.
	Privileged func() bool
	// Now returns the current time (default time.Now).
	Now func() time.Time
}

// collectorResult is what one collector hands back to Collect.
type collectorResult struct {
	apply     func(*Runtime)
	errs      []CollectorError
	truncated []string
}

type collectorFunc func(ctx context.Context, e *env) collectorResult

var collectorFuncs = map[string]collectorFunc{
	CollectorKernel:         collectKernel,
	CollectorListeners:      collectListeners,
	CollectorPackagesInUse:  collectPackagesInUse,
	CollectorServices:       collectServices,
	CollectorVirtualization: collectVirtualization,
}

// env is the shared state of one collection run.
type env struct {
	root           string
	packageManager string
	run            CommandRunner
	privileged     func() bool

	dpkgOnce sync.Once
	dpkg     *dpkgIndex
	dpkgErr  error

	rootOnce sync.Once
	rootID   fileID
	rootOK   bool
}

// path returns the absolute path of p (an absolute path on the target
// system) below the configured root.
func (e *env) path(p string) string {
	if e.root == "/" || e.root == "" {
		return p
	}
	return filepath.Join(e.root, p)
}

// dpkgIndex returns the dpkg file index, building it at most once per run.
func (e *env) dpkgIndex() (*dpkgIndex, error) {
	e.dpkgOnce.Do(func() {
		if e.packageManager != "dpkg" {
			e.dpkgErr = fmt.Errorf("unsupported package manager %q", e.packageManager)
			return
		}
		e.dpkg, e.dpkgErr = buildDpkgIndex(e)
	})
	return e.dpkg, e.dpkgErr
}

// ValidCollector reports whether name is a known collector.
func ValidCollector(name string) bool {
	_, ok := collectorFuncs[name]
	return ok
}

// Collect runs the selected collectors concurrently within the time budget
// and assembles the runtime object. It never fails: problems are recorded in
// the Errors field of the result.
func Collect(ctx context.Context, opts Options) *Runtime {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	root := opts.Root
	if root == "" {
		root = "/"
	}
	run := opts.Run
	if run == nil {
		run = ExecRunner
	}
	privileged := opts.Privileged
	if privileged == nil {
		privileged = HasProcAccess
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	rt := &Runtime{
		SchemaVersion: SchemaVersion,
		CollectedAt:   now().UTC().Format(time.RFC3339),
	}

	selected := map[string]bool{}
	if opts.Collectors == nil {
		for _, c := range AllCollectors {
			selected[c] = true
		}
	} else {
		for _, c := range opts.Collectors {
			selected[c] = true
		}
	}

	e := &env{root: root, packageManager: opts.PackageManager, run: run, privileged: privileged}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type done struct {
		name string
		res  collectorResult
	}
	// Buffered so collectors that finish after the deadline do not block.
	ch := make(chan done, len(AllCollectors))
	pending := map[string]bool{}
	for _, name := range AllCollectors {
		if !selected[name] {
			continue
		}
		pending[name] = true
		go func(name string) {
			ch <- done{name: name, res: collectorFuncs[name](ctx, e)}
		}(name)
	}

	results := map[string]collectorResult{}
wait:
	for len(pending) > 0 {
		select {
		case d := <-ch:
			delete(pending, d.name)
			results[d.name] = d.res
		case <-ctx.Done():
			break wait
		}
	}

	for _, name := range AllCollectors {
		if pending[name] {
			rt.addError(categoryOf[name], "timeout: collector did not finish within the time budget")
			continue
		}
		res, ok := results[name]
		if !ok {
			continue
		}
		// Collectors that notice the deadline themselves return an error
		// result without apply, so partial data never looks complete.
		if res.apply != nil {
			res.apply(rt)
		}
		rt.Errors = append(rt.Errors, res.errs...)
		rt.Truncated = append(rt.Truncated, res.truncated...)
	}

	rt.normalize()
	return rt
}

// addError records an error for a category.
func (r *Runtime) addError(category, msg string) {
	r.Errors = append(r.Errors, CollectorError{Collector: category, Error: msg})
}

// normalize sorts and de-duplicates Errors and Truncated, and turns empty
// lists into nil so they are omitted from the JSON.
func (r *Runtime) normalize() {
	sort.SliceStable(r.Errors, func(i, j int) bool {
		if r.Errors[i].Collector != r.Errors[j].Collector {
			return r.Errors[i].Collector < r.Errors[j].Collector
		}
		return r.Errors[i].Error < r.Errors[j].Error
	})
	if len(r.Errors) == 0 {
		r.Errors = nil
	}
	r.Truncated = sortedUnique(r.Truncated)
	if len(r.Truncated) == 0 {
		r.Truncated = nil
	}
}

// Encode serializes the runtime object and enforces the 1 MB limit: first the
// module index lists are dropped (the hash stays, so the index is retried next
// time), then packagesInUse is omitted. It returns an error when the object is
// still too large; the caller must then omit the runtime object entirely.
func (r *Runtime) Encode() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(b) > maxRuntimeBytes && r.Kernel != nil && r.Kernel.ModuleIndex != nil && r.Kernel.ModuleIndex.Available != nil {
		r.Kernel.ModuleIndex.Available = nil
		r.Kernel.ModuleIndex.Builtin = nil
		if b, err = json.Marshal(r); err != nil {
			return nil, err
		}
	}
	if len(b) > maxRuntimeBytes && r.PackagesInUse != nil {
		r.PackagesInUse = nil
		r.addError(categoryPackagesInUse, "omitted: runtime object exceeds the size limit")
		r.normalize()
		if b, err = json.Marshal(r); err != nil {
			return nil, err
		}
	}
	if len(b) > maxRuntimeBytes {
		return nil, fmt.Errorf("runtime object is %d bytes, limit is %d", len(b), maxRuntimeBytes)
	}
	return b, nil
}

// FullModuleIndexHash returns the module index hash when the full index
// (not only the hash) is part of the object, and "" otherwise. After the
// report was accepted, the caller stores this hash in the state file.
func (r *Runtime) FullModuleIndexHash() string {
	if r.Kernel == nil || r.Kernel.ModuleIndex == nil || r.Kernel.ModuleIndex.Available == nil {
		return ""
	}
	return r.Kernel.ModuleIndex.Hash
}

// ExecRunner runs a command with a neutral locale and without pager or colors.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%w: %s", err, firstLine(msg))
		}
		return out, err
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// sortedUnique returns the sorted, de-duplicated strings of s.
func sortedUnique(s []string) []string {
	if len(s) == 0 {
		return s
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	n := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[n-1] {
			out[n] = out[i]
			n++
		}
	}
	return out[:n]
}

func ptr[T any](v T) *T { return &v }
