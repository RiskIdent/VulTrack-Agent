package runtimefacts

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// pkgFixture builds a root with a dpkg database in a temporary directory.
// Modes (setuid, execute bits) are set here because git does not keep them.
type pkgFixture struct {
	t    *testing.T
	root string
}

func newPkgFixture(t *testing.T) *pkgFixture {
	t.Helper()
	f := &pkgFixture{t: t, root: t.TempDir()}
	for _, dir := range []string{"usr/bin", "usr/sbin", "usr/lib", "var/lib/dpkg/info"} {
		if err := os.MkdirAll(filepath.Join(f.root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// merged /usr
	for _, l := range []string{"bin", "sbin", "lib"} {
		if err := os.Symlink("usr/"+l, filepath.Join(f.root, l)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// file creates a file below the root with the given mode.
func (f *pkgFixture) file(p string, mode os.FileMode) {
	f.t.Helper()
	full := filepath.Join(f.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *pkgFixture) symlink(p, target string) {
	f.t.Helper()
	full := filepath.Join(f.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		f.t.Fatal(err)
	}
}

func (f *pkgFixture) dir(p string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.root, p), 0755); err != nil {
		f.t.Fatal(err)
	}
}

// list writes /var/lib/dpkg/info/<name>.list ("/." plus the paths).
func (f *pkgFixture) list(name string, paths ...string) {
	f.t.Helper()
	content := "/.\n" + strings.Join(paths, "\n") + "\n"
	mustWrite(f.t, filepath.Join(f.root, "var/lib/dpkg/info", name+".list"), content)
}

func (f *pkgFixture) status(content string) {
	mustWrite(f.t, filepath.Join(f.root, "var/lib/dpkg/status"), content)
}

func (f *pkgFixture) collect() *Runtime {
	f.t.Helper()
	return Collect(context.Background(), Options{
		Root:           f.root,
		PackageManager: "dpkg",
		Collectors:     []string{CollectorPackageInfo},
		Privileged:     func() bool { return false },
		Now:            func() time.Time { return fixtureTime },
		Timeout:        10 * time.Second,
	})
}

const pkgFixtureStatus = `Package: tool
Status: install ok installed
Architecture: amd64
Pre-Depends: libc6 (>= 2.34)
Depends: libfoo1 (>= 1.2), libc6:any, missing-pkg, default-mta | mail-transport-agent,
 tool
Recommends: helperpkg [amd64]

Package: legacy
Status: install ok installed

Package: helperpkg
Status: install ok installed

Package: suidpkg
Status: install ok installed

Package: unitpkg
Status: install ok installed

Package: cronpkg
Status: install ok installed

Package: libpam-modules
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Depends: libc6

Package: libpam-modules
Status: install ok installed
Architecture: i386
Multi-Arch: same
Depends: libfoo1:i386 (>= 1)

Package: libnss-pkg
Status: install ok installed

Package: libfoo1
Status: install ok installed
Depends: libc6

Package: libc6
Status: install ok installed

Package: python3-x
Status: install ok installed

Package: profilepkg
Status: install ok installed

Package: docpkg
Status: install ok installed

Package: orig
Status: install ok installed

Package: divpkg
Status: install ok installed

Package: deleted
Status: install ok installed

Package: postfix
Status: install ok installed
Provides: mail-transport-agent, default-mta-virtual (= 1)

Package: exim4-daemon-light
Status: install ok installed
Provides: mail-transport-agent

Package: held
Status: hold ok installed

Package: halfinst
Status: install reinstreq half-installed

Package: removed
Status: deinstall ok config-files
Provides: libc6

Package: purged
Status: purge ok not-installed
`

func buildPkgFixture(t *testing.T) *pkgFixture {
	f := newPkgFixture(t)
	f.status(pkgFixtureStatus)

	f.file("usr/bin/tool", 0755)
	f.list("tool", "/usr", "/usr/bin", "/usr/bin/tool")

	f.file("usr/bin/legacy", 0755)
	f.list("legacy", "/bin", "/bin/legacy") // merged /usr, listed without /usr

	f.file("usr/lib/helperpkg/helper", 0755)
	f.file("usr/lib/helperpkg/data.txt", 0644)
	f.list("helperpkg", "/usr/lib/helperpkg", "/usr/lib/helperpkg/helper", "/usr/lib/helperpkg/data.txt")

	f.file("usr/lib/suidpkg/check", 0644|os.ModeSetuid)
	f.list("suidpkg", "/usr/lib/suidpkg/check")

	f.file("usr/lib/systemd/system/unit.service", 0644)
	f.list("unitpkg", "/usr/lib/systemd/system/unit.service")

	f.file("etc/cron.d/cronpkg", 0644)
	f.list("cronpkg", "/etc/cron.d", "/etc/cron.d/cronpkg")

	f.file("usr/lib/x86_64-linux-gnu/security/pam_unix.so", 0644)
	f.list("libpam-modules:amd64", "/usr/lib/x86_64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so")
	f.file("etc/pam.d/other", 0644)
	f.list("libpam-modules:i386", "/etc/pam.d/other")

	f.file("usr/lib/x86_64-linux-gnu/libnss_files.so.2", 0644)
	f.list("libnss-pkg", "/usr/lib/x86_64-linux-gnu/libnss_files.so.2")

	f.file("usr/lib/x86_64-linux-gnu/libfoo.so.1.2.3", 0644)
	f.symlink("usr/lib/x86_64-linux-gnu/libfoo.so.1", "libfoo.so.1.2.3")
	f.list("libfoo1", "/usr", "/usr/lib", "/usr/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu/libfoo.so.1.2.3", "/usr/lib/x86_64-linux-gnu/libfoo.so.1")

	f.list("libc6")

	f.file("usr/lib/python3/dist-packages/x/__init__.py", 0644)
	f.list("python3-x", "/usr/lib/python3", "/usr/lib/python3/dist-packages",
		"/usr/lib/python3/dist-packages/x", "/usr/lib/python3/dist-packages/x/__init__.py")

	f.file("etc/profile.d/p.sh", 0644)
	f.list("profilepkg", "/etc/profile.d/p.sh")

	// Only directories and docs. The drop-in directory is listed without
	// children; lstat must recognise it as a directory.
	f.file("usr/share/doc/docpkg/copyright", 0755)
	f.dir("usr/lib/systemd/system/docpkg.service.d")
	f.list("docpkg", "/usr", "/usr/share", "/usr/share/doc", "/usr/share/doc/docpkg",
		"/usr/share/doc/docpkg/copyright", "/usr/lib/systemd/system/docpkg.service.d")

	// divpkg diverts orig's /usr/lib/orig/run to run.distrib.
	f.file("usr/lib/orig/run", 0644)
	f.file("usr/lib/orig/run.distrib", 0755)
	f.list("orig", "/usr/lib/orig/run")
	f.list("divpkg", "/usr/lib/orig/run")
	mustWrite(t, filepath.Join(f.root, "var/lib/dpkg/diversions"),
		"/usr/lib/orig/run\n/usr/lib/orig/run.distrib\ndivpkg\n")

	// Files removed by an administrator: only the path rules apply.
	f.list("deleted", "/usr/lib/deleted/gone", "/usr/sbin/gone")

	f.list("postfix")
	f.list("exim4-daemon-light")
	f.list("held")
	f.list("halfinst")
	return f
}

func TestPackageInfo(t *testing.T) {
	r := buildPkgFixture(t).collect()
	if r.Errors != nil || r.Truncated != nil {
		t.Fatalf("errors: %+v truncated: %v", r.Errors, r.Truncated)
	}
	got := map[string]PackageInfo{}
	var order []string
	for _, p := range *r.PackageInfo {
		got[p.Package] = p
		order = append(order, p.Package)
	}

	want := map[string]PackageInfo{
		"tool": {EntryPoints: []string{"executable"},
			// tool itself, missing-pkg and default-mta are dropped; the
			// virtual mail-transport-agent becomes both providers.
			Depends: []string{"exim4-daemon-light", "helperpkg", "libc6", "libfoo1", "postfix"}},
		"legacy":             {EntryPoints: []string{"executable"}},
		"helperpkg":          {EntryPoints: []string{"executable"}},
		"suidpkg":            {EntryPoints: []string{"executable"}},
		"unitpkg":            {EntryPoints: []string{"service"}},
		"cronpkg":            {EntryPoints: []string{"service"}},
		"libpam-modules":     {EntryPoints: []string{"hook", "plugin"}, Depends: []string{"libc6", "libfoo1"}},
		"libnss-pkg":         {EntryPoints: []string{"plugin"}},
		"libfoo1":            {Depends: []string{"libc6"}},
		"libc6":              {},
		"python3-x":          {EntryPoints: []string{"plugin"}},
		"profilepkg":         {EntryPoints: []string{"hook"}},
		"docpkg":             {},
		"orig":               {EntryPoints: []string{"executable"}},
		"divpkg":             {},
		"deleted":            {EntryPoints: []string{"executable"}},
		"postfix":            {},
		"exim4-daemon-light": {},
		"held":               {},
		"halfinst":           {},
	}
	for name, w := range want {
		w.Package = name
		g, ok := got[name]
		if !ok {
			t.Errorf("%s: missing", name)
			continue
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: got %+v, want %+v", name, g, w)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected package %s", name)
		}
	}
	if !sortedStrings(order) {
		t.Errorf("entries not sorted: %v", order)
	}
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

// A file that cannot be inspected counts as executable.
func TestPackageInfoUnreadableFileIsExecutable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newPkgFixture(t)
	f.status("Package: secret\nStatus: install ok installed\n")
	f.file("usr/lib/secret/data", 0644)
	f.list("secret", "/usr/lib/secret/data")
	dir := filepath.Join(f.root, "usr/lib/secret")
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755)
	r := f.collect()
	if r.PackageInfo == nil || !reflect.DeepEqual((*r.PackageInfo)[0].EntryPoints, []string{"executable"}) {
		t.Errorf("got %+v, errors %+v", r.PackageInfo, r.Errors)
	}
}

// All or nothing: a broken file list or a package without one omits the
// whole category.
func TestPackageInfoAllOrNothing(t *testing.T) {
	t.Run("unreadable list", func(t *testing.T) {
		f := buildPkgFixture(t)
		// A directory in place of the list cannot be read, also as root.
		f.dir("var/lib/dpkg/info/broken.list")
		r := f.collect()
		if r.PackageInfo != nil || len(r.Errors) != 1 || r.Errors[0].Collector != "packageInfo" {
			t.Errorf("packageInfo: %v errors: %+v", r.PackageInfo, r.Errors)
		}
	})
	t.Run("missing list", func(t *testing.T) {
		f := buildPkgFixture(t)
		if err := os.Remove(filepath.Join(f.root, "var/lib/dpkg/info/held.list")); err != nil {
			t.Fatal(err)
		}
		r := f.collect()
		want := []CollectorError{{Collector: "packageInfo", Error: "package held: no dpkg file list"}}
		if r.PackageInfo != nil || !reflect.DeepEqual(r.Errors, want) {
			t.Errorf("packageInfo: %v errors: %+v", r.PackageInfo, r.Errors)
		}
	})
	t.Run("missing status", func(t *testing.T) {
		f := buildPkgFixture(t)
		if err := os.Remove(filepath.Join(f.root, "var/lib/dpkg/status")); err != nil {
			t.Fatal(err)
		}
		r := f.collect()
		if r.PackageInfo != nil || len(r.Errors) != 1 {
			t.Errorf("packageInfo: %v errors: %+v", r.PackageInfo, r.Errors)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := buildPkgFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res := collectPackageInfo(ctx, &env{root: f.root, packageManager: "dpkg"})
		if res.apply != nil || len(res.errs) != 1 || !strings.HasPrefix(res.errs[0].Error, "timeout") {
			t.Errorf("got %+v", res)
		}
	})
}

func TestPackageInfoTruncation(t *testing.T) {
	defer func(n int) { maxPackageInfo = n }(maxPackageInfo)
	maxPackageInfo = 3
	r := buildPkgFixture(t).collect()
	if len(*r.PackageInfo) != 3 || !reflect.DeepEqual(r.Truncated, []string{"packageInfo"}) {
		t.Errorf("got %d entries, truncated %v", len(*r.PackageInfo), r.Truncated)
	}
	if (*r.PackageInfo)[0].Package != "cronpkg" {
		t.Errorf("cap must keep the first entries, got %v", (*r.PackageInfo)[0])
	}
}

func TestRelationNames(t *testing.T) {
	got := relationNames("libc6 (>= 2.34), libssl3t64|libssl3 , perl:any, foo [amd64], bar:amd64 (= 1) [!i386], ")
	want := []string{"libc6", "libssl3t64", "libssl3", "perl", "foo", "bar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEntryPointRules(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"/usr/bin/x", []string{"executable"}},
		{"/usr/local/sbin/x", []string{"executable"}},
		{"/usr/libexec/foo/helper", []string{"executable"}},
		{"/usr/lib/systemd/system-generators/g", []string{"service"}},
		{"/usr/lib/systemd/system/x.service", []string{"service"}},
		{"/etc/init.d/x", []string{"service"}},
		{"/usr/share/dbus-1/system-services/x.service", []string{"service"}},
		{"/etc/xdg/autostart/x.desktop", []string{"service"}},
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", nil},
		{"/usr/lib/x86_64-linux-gnu/libfoo.so", nil},
		{"/usr/lib/libfoo.so.1.2", nil},
		{"/usr/lib/arm-linux-gnueabihf/libfoo.so.1", nil},
		{"/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2", []string{"plugin"}},
		{"/usr/lib/x86_64-linux-gnu/gconv/UTF-16.so", []string{"plugin"}},
		{"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so", []string{"plugin"}},
		{"/usr/lib/x86_64-linux-gnu/libfoo.so.1.debug", nil},
		{"/usr/lib/x86_64-linux-gnu/libfoo.sox", nil},
		{"/usr/lib/python3.12/os.py", []string{"plugin"}},
		{"/usr/lib/python2.7/os.py", []string{"plugin"}},
		{"/usr/lib/x86_64-linux-gnu/perl5/5.38/x.pm", []string{"plugin"}},
		{"/usr/lib/x86_64-linux-gnu/perl-base/x.pm", []string{"plugin"}},
		{"/usr/share/perl5/x.pm", []string{"plugin"}},
		{"/usr/share/nodejs/x/index.js", []string{"plugin"}},
		{"/etc/network/if-up.d/x", []string{"hook"}},
		{"/etc/network/interfaces", nil},
		{"/etc/ld.so.preload", []string{"hook"}},
		{"/usr/lib/apt/methods/https", []string{"hook"}},
		{"/usr/lib/udev/rules.d/60-x.rules", []string{"hook"}},
		{"/etc/cron.daily/x", []string{"service"}},
		{"/etc/cron.dx/x", nil},
		{"/usr/share/doc/x/copyright", nil},
		{usrForm("/lib/systemd/system/ssh.service"), []string{"service"}},
		{usrForm("/sbin/x"), []string{"executable"}},
		{usrForm("/lib/x86_64-linux-gnu/security/pam_unix.so"), []string{"plugin"}},
	}
	for _, tt := range tests {
		kinds := map[string]bool{}
		pathKinds(tt.path, kinds)
		var got []string
		for k := range kinds {
			got = append(got, k)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.path, got, tt.want)
		}
	}
}

// The dpkg index is built once and shared by packagesInUse and packageInfo.
func TestPackageInfoSharesDpkgIndex(t *testing.T) {
	e := fixtureEnv(t)
	collectPackagesInUse(context.Background(), e)
	idx := e.dpkg
	if idx == nil {
		t.Fatal("packagesInUse did not build the index")
	}
	if res := collectPackageInfo(context.Background(), e); res.apply == nil || e.dpkg != idx {
		t.Errorf("packageInfo must reuse the index: %+v", res.errs)
	}
}
