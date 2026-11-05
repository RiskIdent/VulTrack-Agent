package runtimefacts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
)

// PackageInfo describes one installed package: the kinds of entry points it
// ships and the installed packages it depends on.
//
// The backend trusts the absence of entry points and dependencies, so the
// collector over-reports when in doubt and sends all packages or none.
type PackageInfo struct {
	Package     string   `json:"package"`
	EntryPoints []string `json:"entryPoints,omitempty"`
	Depends     []string `json:"depends,omitempty"`
}

// Entry point kinds.
const (
	entryExecutable = "executable"
	entryService    = "service"
	entryPlugin     = "plugin"
	entryHook       = "hook"
)

// installedStates are the dpkg package states in which files of the package
// may be on disk. The selection (install, hold, ...) does not matter.
var installedStates = map[string]bool{
	"installed":        true,
	"half-installed":   true,
	"half-configured":  true,
	"unpacked":         true,
	"triggers-awaited": true,
	"triggers-pending": true,
}

// Directories (and single files) whose contents are entry points of a kind.
// A path matches when it equals an entry or lies below it. Paths are compared
// in their /usr form (see usrForm).
var (
	executableDirs = []string{
		"/usr/bin", "/usr/sbin", "/usr/games", "/usr/libexec",
		"/usr/local/bin", "/usr/local/sbin",
	}
	serviceDirs = []string{
		"/usr/lib/systemd/system", "/usr/lib/systemd/user",
		"/etc/systemd/system", "/etc/systemd/user",
		"/usr/lib/systemd/system-generators", "/usr/lib/systemd/user-generators",
		"/etc/init.d",
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
		"/usr/share/dbus-1/services", "/usr/share/dbus-1/system-services",
		"/etc/xdg/autostart",
	}
	// Interpreter module directories; /usr/lib/python3*, /usr/lib/python2*
	// and /usr/lib/<triplet>/perl* are handled in isInterpreterModule.
	interpreterDirs = []string{
		"/usr/share/python3", "/usr/share/perl5",
		"/usr/lib/ruby", "/usr/share/ruby",
		"/usr/lib/nodejs", "/usr/share/nodejs",
		"/usr/lib/php", "/usr/share/php",
	}
	// Hook directories; /etc/network/if-*.d is handled in isHook.
	hookDirs = []string{
		"/etc/profile.d", "/etc/X11/Xsession.d", "/etc/apt/apt.conf.d",
		"/usr/lib/apt/methods", "/etc/kernel/postinst.d", "/etc/kernel/postrm.d",
		"/etc/update-motd.d", "/etc/NetworkManager/dispatcher.d",
		"/usr/lib/udev/rules.d", "/etc/udev/rules.d", "/etc/pam.d",
		"/etc/ld.so.conf.d", "/etc/ld.so.preload",
		"/usr/lib/systemd/system-sleep", "/usr/lib/systemd/system-shutdown",
	}
	// Paths below these directories are never executable in practice; the
	// execute-bit check is skipped for them to save time.
	noStatDirs = []string{
		"/usr/share/doc", "/usr/share/man", "/usr/share/info",
		"/usr/share/locale", "/usr/include",
	}
)

func collectPackageInfo(ctx context.Context, e *env) collectorResult {
	idx, err := e.dpkgIndex()
	if err != nil {
		return errResult(categoryPackageInfo, "package lookup unavailable: "+err.Error())
	}
	status, err := readDpkgStatus(e.path("/var/lib/dpkg/status"))
	if err != nil {
		return errResult(categoryPackageInfo, err.Error())
	}

	// Merge the stanzas of packages installed for several architectures.
	type pkgData struct{ deps []string }
	pkgs := map[string]*pkgData{}
	provides := map[string]map[string]bool{}
	for _, st := range status {
		if !installedStates[st.state] {
			continue
		}
		p, ok := pkgs[st.name]
		if !ok {
			p = &pkgData{}
			pkgs[st.name] = p
		}
		p.deps = append(p.deps, st.depends...)
		for _, v := range st.provides {
			if provides[v] == nil {
				provides[v] = map[string]bool{}
			}
			provides[v][st.name] = true
		}
	}

	names := make([]string, 0, len(pkgs))
	for name := range pkgs {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]PackageInfo, 0, len(names))
	for _, name := range names {
		if ctx.Err() != nil {
			return timeoutResult(categoryPackageInfo, ctx)
		}
		files, ok := idx.files[name]
		if !ok {
			return errResult(categoryPackageInfo, fmt.Sprintf("package %s: no dpkg file list", name))
		}
		info := PackageInfo{Package: name}
		if kinds := entryPoints(e, idx, name, files); len(kinds) > 0 {
			info.EntryPoints = kinds
		}
		if deps := resolveDepends(name, pkgs[name].deps, func(n string) bool { _, ok := pkgs[n]; return ok }, provides); len(deps) > 0 {
			info.Depends = deps
		}
		result = append(result, info)
	}

	res := collectorResult{}
	if len(result) > maxPackageInfo {
		result = result[:maxPackageInfo]
		res.truncated = []string{categoryPackageInfo}
	}
	res.apply = func(r *Runtime) { r.PackageInfo = &result }
	return res
}

// entryPoints returns the sorted kinds of entry points among the files of
// one package.
func entryPoints(e *env, idx *dpkgIndex, pkg string, files []string) []string {
	// A listed path with another listed path below it is a directory.
	dirs := map[string]bool{}
	for _, p := range files {
		for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
			if dirs[d] {
				break
			}
			dirs[d] = true
		}
	}

	kinds := map[string]bool{}
	for _, p := range files {
		if dirs[p] || !strings.HasPrefix(p, "/") {
			continue
		}
		u := usrForm(path.Clean(p))
		candidates := []string{u}

		// A file another package diverted away lives at the diversion target.
		onDisk := p
		if d, ok := idx.diversionOf(p); ok && d.by != pkg {
			onDisk = d.to
			candidates = append(candidates, usrForm(path.Clean(d.to)))
		}

		if !underAny(u, noStatDirs) {
			fi, err := os.Lstat(e.path(onDisk))
			switch {
			case err == nil:
				if fi.IsDir() {
					continue
				}
				m := fi.Mode()
				if (m.IsRegular() && m.Perm()&0111 != 0) || m&(os.ModeSetuid|os.ModeSetgid) != 0 {
					kinds[entryExecutable] = true
				}
			case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
				// Deleted by an administrator: only the path rules apply.
			default:
				// Cannot tell, so over-report.
				kinds[entryExecutable] = true
			}
		}

		for _, c := range candidates {
			pathKinds(c, kinds)
		}
	}

	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pathKinds adds the entry point kinds that follow from the path u (in /usr
// form) alone.
func pathKinds(u string, kinds map[string]bool) {
	if underAny(u, executableDirs) {
		kinds[entryExecutable] = true
	}
	if underAny(u, serviceDirs) {
		kinds[entryService] = true
	}
	if isPlugin(u) {
		kinds[entryPlugin] = true
	}
	if isHook(u) {
		kinds[entryHook] = true
	}
}

// usrForm maps a path below a top-level directory that merged /usr moves
// into /usr (/bin, /sbin, /lib*) to its /usr path. It is applied on every
// system, merged or not, so that e.g. /lib/systemd/system units match.
func usrForm(p string) string {
	top, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	switch top {
	case "bin", "sbin", "lib", "lib32", "lib64", "libx32":
		return "/usr" + p
	}
	return p
}

// under reports whether p equals dir or lies below it.
func under(p, dir string) bool {
	return strings.HasPrefix(p, dir) && (len(p) == len(dir) || p[len(dir)] == '/')
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if under(p, d) {
			return true
		}
	}
	return false
}

func isPlugin(u string) bool {
	base := path.Base(u)
	if isSharedObject(base) && (!isStandardLibDir(path.Dir(u)) || strings.HasPrefix(base, "libnss_")) {
		return true
	}
	return isInterpreterModule(u)
}

// isSharedObject reports whether name is "*.so" or "*.so.<digits and dots>".
func isSharedObject(name string) bool {
	for i := strings.Index(name, ".so"); i >= 0; {
		if i > 0 {
			rest := name[i+3:]
			if rest == "" {
				return true
			}
			if rest[0] == '.' && len(rest) > 1 && strings.Trim(rest[1:], "0123456789.") == "" {
				return true
			}
		}
		j := strings.Index(name[i+3:], ".so")
		if j < 0 {
			break
		}
		i += 3 + j
	}
	return false
}

// isStandardLibDir reports whether dir is a directory of the dynamic linker's
// default search path. Anything else (including unknown triplets) counts as
// non-standard, so shared objects there are reported as plugins.
func isStandardLibDir(dir string) bool {
	switch dir {
	case "/usr/lib", "/usr/lib64", "/usr/lib32":
		return true
	}
	t, ok := strings.CutPrefix(dir, "/usr/lib/")
	return ok && isTriplet(t)
}

// isTriplet reports whether s is a Debian multiarch triplet such as
// x86_64-linux-gnu or arm-linux-gnueabihf.
func isTriplet(s string) bool {
	cpu, rest, ok := strings.Cut(s, "-linux-gnu")
	if !ok || cpu == "" || strings.Contains(rest, "/") {
		return false
	}
	valid := func(r rune) bool { return r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }
	return strings.IndexFunc(cpu, func(r rune) bool { return !valid(r) }) < 0 &&
		strings.IndexFunc(rest, func(r rune) bool { return !valid(r) }) < 0
}

func isInterpreterModule(u string) bool {
	if underAny(u, interpreterDirs) {
		return true
	}
	if rest, ok := strings.CutPrefix(u, "/usr/lib/"); ok {
		if strings.HasPrefix(rest, "python3") || strings.HasPrefix(rest, "python2") {
			return true
		}
		triplet, sub, ok := strings.Cut(rest, "/")
		if ok && isTriplet(triplet) && strings.HasPrefix(sub, "perl") {
			return true
		}
	}
	return false
}

func isHook(u string) bool {
	if underAny(u, hookDirs) {
		return true
	}
	if rest, ok := strings.CutPrefix(u, "/etc/network/"); ok {
		comp, _, _ := strings.Cut(rest, "/")
		return strings.HasPrefix(comp, "if-") && strings.HasSuffix(comp, ".d")
	}
	return false
}

// diversionOf returns the diversion of p, also when it is recorded under the
// merged-/usr spelling of p.
func (idx *dpkgIndex) diversionOf(p string) (diversion, bool) {
	for _, v := range idx.variants(path.Clean(p)) {
		if d, ok := idx.diversions[v]; ok {
			return d, true
		}
	}
	return diversion{}, false
}

// resolveDepends turns raw dependency names into the sorted installed
// packages they refer to: installed names as they are, virtual names as their
// installed providers. Unknown names and the package itself are dropped.
func resolveDepends(self string, raw []string, installed func(string) bool, provides map[string]map[string]bool) []string {
	set := map[string]bool{}
	for _, n := range raw {
		if installed(n) {
			set[n] = true
			continue
		}
		for p := range provides[n] {
			set[p] = true
		}
	}
	delete(set, self)
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// statusEntry is one stanza of /var/lib/dpkg/status.
type statusEntry struct {
	name     string
	state    string   // third word of Status
	depends  []string // names from Depends, Pre-Depends and Recommends
	provides []string // names from Provides
}

// readDpkgStatus parses the fields of /var/lib/dpkg/status needed for
// packageInfo. Continuation lines are joined to their field.
func readDpkgStatus(file string) ([]statusEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []statusEntry
	fields := map[string]string{}
	last := ""
	flush := func() {
		if name := fields["Package"]; name != "" {
			st := strings.Fields(fields["Status"])
			e := statusEntry{name: name}
			if len(st) == 3 {
				e.state = st[2]
			}
			for _, k := range []string{"Depends", "Pre-Depends", "Recommends"} {
				e.depends = append(e.depends, relationNames(fields[k])...)
			}
			e.provides = relationNames(fields["Provides"])
			entries = append(entries, e)
		}
		clear(fields)
		last = ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			if last != "" {
				fields[last] += " " + strings.TrimSpace(line)
			}
		default:
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				last = ""
				continue
			}
			last = k
			fields[k] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return entries, nil
}

// relationNames extracts the package names of a dpkg relationship field such
// as "libc6 (>= 2.34), libssl3t64 | libssl3, perl:any, foo [amd64]".
// Alternatives all count; versions, architecture qualifiers and architecture
// restrictions are dropped.
func relationNames(field string) []string {
	var out []string
	for _, group := range strings.Split(field, ",") {
		for _, alt := range strings.Split(group, "|") {
			alt = strings.TrimSpace(alt)
			if i := strings.IndexAny(alt, " \t([<"); i >= 0 {
				alt = alt[:i]
			}
			if i := strings.IndexByte(alt, ':'); i >= 0 {
				alt = alt[:i]
			}
			if alt != "" {
				out = append(out, alt)
			}
		}
	}
	return out
}
