package runtimefacts

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// Kernel holds the kernel facts. Every field except Release is optional:
// nil means "could not be determined" (the reason is in Runtime.Errors).
type Kernel struct {
	Release                string               `json:"release"`
	ModulesDisabled        *bool                `json:"modulesDisabled,omitempty"`
	LoadedModules          *[]LoadedModule      `json:"loadedModules,omitempty"`
	BlacklistedModules     *[]BlacklistedModule `json:"blacklistedModules,omitempty"`
	ModuleIndex            *ModuleIndex         `json:"moduleIndex,omitempty"`
	Sysctls                *map[string]string   `json:"sysctls,omitempty"`
	InstalledKernels       *[]string            `json:"installedKernels,omitempty"`
	RebootRequired         *bool                `json:"rebootRequired,omitempty"`
	RebootRequiredPackages *[]string            `json:"rebootRequiredPackages,omitempty"`
}

// LoadedModule is a module from /proc/modules.
type LoadedModule struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// BlacklistedModule is a module blacklisted or disabled in modprobe.d.
type BlacklistedModule struct {
	Name           string `json:"name"`
	InstallCommand string `json:"installCommand,omitempty"`
}

// ModuleIndex lists the modules available for the running kernel. Available
// and Builtin are nil when only the hash is sent.
type ModuleIndex struct {
	Hash      string    `json:"hash"`
	Available *[]string `json:"available,omitempty"`
	Builtin   *[]string `json:"builtin,omitempty"`
}

// sysctlKeys are the kernel settings reported in Kernel.Sysctls.
var sysctlKeys = []string{
	"kernel.unprivileged_userns_clone",
	"user.max_user_namespaces",
	"kernel.apparmor_restrict_unprivileged_userns",
	"kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope",
	"kernel.kptr_restrict",
	"kernel.dmesg_restrict",
	"kernel.perf_event_paranoid",
	"kernel.modules_disabled",
}

// modprobeDirs in precedence order: a file in an earlier directory replaces a
// file with the same name in a later one.
var modprobeDirs = []string{
	"/etc/modprobe.d",
	"/run/modprobe.d",
	"/usr/local/lib/modprobe.d",
	"/lib/modprobe.d",
	"/usr/lib/modprobe.d",
}

// disablingCommands are the install commands that prevent a module from
// being loaded.
var disablingCommands = map[string]bool{
	"/bin/false":     true,
	"/bin/true":      true,
	"/usr/bin/false": true,
	"/usr/bin/true":  true,
}

func collectKernel(ctx context.Context, e *env) collectorResult {
	b, err := os.ReadFile(e.path("/proc/sys/kernel/osrelease"))
	if err != nil {
		return errResult(categoryKernel, "kernel release: "+err.Error())
	}
	release := strings.TrimSpace(string(b))
	if release == "" {
		return errResult(categoryKernel, "kernel release is empty")
	}

	k := &Kernel{Release: release}
	var errs []CollectorError
	fail := func(field string, err error) {
		errs = append(errs, CollectorError{Collector: categoryKernel, Error: field + ": " + err.Error()})
	}

	if v, err := os.ReadFile(e.path("/proc/sys/kernel/modules_disabled")); err != nil {
		fail("modulesDisabled", err)
	} else {
		k.ModulesDisabled = ptr(strings.TrimSpace(string(v)) == "1")
	}

	modDir := "/lib/modules/" + release
	available, depErr := readModulesDep(e.path(modDir + "/modules.dep"))

	if mods, err := readProcModules(e.path("/proc/modules")); err != nil {
		fail("loadedModules", err)
	} else {
		paths := modulePathsByName(available)
		for i := range mods {
			mods[i].Path = paths[mods[i].Name]
		}
		k.LoadedModules = &mods
	}

	if bl, err := readBlacklist(e); err != nil {
		fail("blacklistedModules", err)
	} else {
		k.BlacklistedModules = &bl
	}

	if depErr != nil {
		fail("moduleIndex", depErr)
	} else if builtin, err := readLines(e.path(modDir + "/modules.builtin")); err != nil {
		fail("moduleIndex", err)
	} else {
		sort.Strings(available)
		sort.Strings(builtin)
		k.ModuleIndex = &ModuleIndex{
			Hash:      ModuleIndexHash(release, available, builtin),
			Available: &available,
			Builtin:   &builtin,
		}
	}

	sysctls := map[string]string{}
	for _, key := range sysctlKeys {
		v, err := os.ReadFile(e.path("/proc/sys/" + strings.ReplaceAll(key, ".", "/")))
		if err != nil {
			continue
		}
		sysctls[key] = strings.TrimSpace(string(v))
	}
	k.Sysctls = &sysctls

	if e.packageManager != "dpkg" {
		fail("installedKernels", fmt.Errorf("unsupported package manager %q", e.packageManager))
	} else if kernels, err := readInstalledKernels(e.path("/var/lib/dpkg/status")); err != nil {
		fail("installedKernels", err)
	} else {
		k.InstalledKernels = &kernels
	}

	// /var/run/reboot-required is a Debian/Ubuntu convention; elsewhere its
	// absence would not mean "no reboot required".
	if e.packageManager != "dpkg" {
		fail("rebootRequired", fmt.Errorf("unsupported package manager %q", e.packageManager))
	} else {
		_, err := os.Stat(e.path("/var/run/reboot-required"))
		switch {
		case err == nil:
			k.RebootRequired = ptr(true)
		case errors.Is(err, fs.ErrNotExist):
			k.RebootRequired = ptr(false)
		default:
			fail("rebootRequired", err)
		}
		pkgs, err := readLines(e.path("/var/run/reboot-required.pkgs"))
		switch {
		case err == nil:
			pkgs = sortedUnique(pkgs)
			k.RebootRequiredPackages = &pkgs
		case !errors.Is(err, fs.ErrNotExist):
			fail("rebootRequiredPackages", err)
		}
	}

	if ctx.Err() != nil {
		return timeoutResult(categoryKernel, ctx)
	}
	return collectorResult{apply: func(r *Runtime) { r.Kernel = k }, errs: errs}
}

// ModuleIndexHash computes "sha256:" + hex SHA-256 over the release, a
// newline, the sorted available paths joined by newlines, a newline and the
// sorted builtin paths joined by newlines.
func ModuleIndexHash(release string, available, builtin []string) string {
	sum := sha256.Sum256([]byte(release + "\n" + strings.Join(available, "\n") + "\n" + strings.Join(builtin, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// readProcModules returns the loaded modules from /proc/modules, sorted.
func readProcModules(file string) ([]LoadedModule, error) {
	lines, err := readLines(file)
	if err != nil {
		return nil, err
	}
	mods := []LoadedModule{}
	seen := map[string]bool{}
	for _, line := range lines {
		name, _, _ := strings.Cut(line, " ")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		mods = append(mods, LoadedModule{Name: name})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	return mods, nil
}

// readModulesDep returns the module paths (left of the colon) of modules.dep.
func readModulesDep(file string) ([]string, error) {
	lines, err := readLines(file)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		p, _, ok := strings.Cut(line, ":")
		if !ok || p == "" {
			continue
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// moduleName derives the module name from a module path:
// "kernel/drivers/net/foo-bar.ko.zst" → "foo_bar".
func moduleName(p string) string {
	base := path.Base(p)
	if i := strings.Index(base, ".ko"); i >= 0 {
		base = base[:i]
	}
	return normalizeModuleName(base)
}

func normalizeModuleName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}

// modulePathsByName maps module names to their path. Names that occur more
// than once are left out, since the loaded one cannot be told apart.
func modulePathsByName(paths []string) map[string]string {
	m := make(map[string]string, len(paths))
	dup := map[string]bool{}
	for _, p := range paths {
		name := moduleName(p)
		if _, ok := m[name]; ok {
			dup[name] = true
			continue
		}
		m[name] = p
	}
	for name := range dup {
		delete(m, name)
	}
	return m
}

// readBlacklist parses the modprobe.d directories with the override rule and
// returns blacklisted or disabled modules, sorted by name.
func readBlacklist(e *env) ([]BlacklistedModule, error) {
	files := map[string]string{} // file name → full path of the winning file
	for _, dir := range modprobeDirs {
		entries, err := os.ReadDir(e.path(dir))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, ent := range entries {
			name := ent.Name()
			if !strings.HasSuffix(name, ".conf") || ent.IsDir() {
				continue
			}
			if _, ok := files[name]; ok {
				continue
			}
			files[name] = e.path(dir + "/" + name)
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	byName := map[string]*BlacklistedModule{}
	for _, name := range names {
		data, err := os.ReadFile(files[name])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		parseModprobeConf(string(data), byName)
	}

	out := make([]BlacklistedModule, 0, len(byName))
	for _, m := range byName {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parseModprobeConf adds the blacklist and disabling install directives of
// one modprobe.d file to byName.
func parseModprobeConf(content string, byName map[string]*BlacklistedModule) {
	for _, line := range joinContinuations(content) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch {
		case fields[0] == "blacklist" && len(fields) == 2:
			name := normalizeModuleName(fields[1])
			if _, ok := byName[name]; !ok {
				byName[name] = &BlacklistedModule{Name: name}
			}
		case fields[0] == "install" && len(fields) >= 3:
			cmd := strings.Join(fields[2:], " ")
			if !disablingCommands[cmd] {
				continue
			}
			name := normalizeModuleName(fields[1])
			m, ok := byName[name]
			if !ok {
				m = &BlacklistedModule{Name: name}
				byName[name] = m
			}
			if m.InstallCommand == "" {
				m.InstallCommand = cmd
			}
		}
	}
}

// joinContinuations splits content into lines, joining lines that end with a
// backslash with the next one.
func joinContinuations(content string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(content, "\n") {
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// readInstalledKernels returns the releases of the installed linux-image
// packages from the dpkg status database, sorted.
func readInstalledKernels(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kernels := []string{}
	var pkg, status string
	flush := func() {
		if status == "install ok installed" {
			if rel, ok := kernelRelease(pkg); ok {
				kernels = append(kernels, rel)
			}
		}
		pkg, status = "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return sortedUnique(kernels), nil
}

// kernelRelease extracts the kernel release from a linux-image package name.
// Meta packages (linux-image-generic) and debug symbol packages are skipped.
// Ubuntu's "linux-image-unsigned-<release>" and Debian's
// "linux-image-<release>-unsigned" carry a real kernel, too.
func kernelRelease(pkg string) (string, bool) {
	rel, ok := strings.CutPrefix(pkg, "linux-image-")
	if !ok {
		return "", false
	}
	rel = strings.TrimPrefix(rel, "unsigned-")
	if strings.HasSuffix(rel, "-dbg") || strings.HasSuffix(rel, "-dbgsym") {
		return "", false
	}
	rel = strings.TrimSuffix(rel, "-unsigned")
	if rel == "" || rel[0] < '0' || rel[0] > '9' {
		return "", false
	}
	return rel, true
}

// readLines returns the non-empty, trimmed lines of a file.
func readLines(file string) ([]string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	lines := []string{}
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
