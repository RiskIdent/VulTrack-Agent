package runtimefacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixtureRoot = "testdata/rootfs"

var fixtureTime = time.Date(2026, 11, 5, 10, 0, 3, 0, time.UTC)

// fakeRunner serves systemctl and systemd-detect-virt from testdata.
func fakeRunner(t *testing.T) CommandRunner {
	t.Helper()
	listUnits, err := os.ReadFile("testdata/systemctl/list-units.txt")
	if err != nil {
		t.Fatal(err)
	}
	show, err := os.ReadFile("testdata/systemctl/show.txt")
	if err != nil {
		t.Fatal(err)
	}
	blocks := map[string]string{}
	for _, b := range strings.Split(string(show), "\n\n") {
		for _, line := range strings.Split(b, "\n") {
			if id, ok := strings.CutPrefix(line, "Id="); ok {
				blocks[id] = strings.TrimSpace(b) + "\n"
			}
		}
	}
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch {
		case name == "systemctl" && args[0] == "list-units":
			return listUnits, nil
		case name == "systemctl" && args[0] == "show":
			if args[1] != "--no-pager" || !strings.HasPrefix(args[2], "--property=") {
				t.Errorf("unexpected systemctl show args %v", args)
			}
			units := args[3:]
			if len(units) == 0 {
				t.Error("systemctl show called without units")
			}
			if len(units) > showBatchSize {
				t.Errorf("systemctl show called with %d units", len(units))
			}
			var out []string
			for _, u := range units {
				out = append(out, blocks[u])
			}
			return []byte(strings.Join(out, "\n")), nil
		case name == "systemd-detect-virt":
			return []byte("kvm\n"), nil
		}
		return nil, exec.ErrNotFound
	}
}

func fixtureOptions(t *testing.T) Options {
	return Options{
		Root:           fixtureRoot,
		PackageManager: "dpkg",
		Run:            fakeRunner(t),
		Privileged:     func() bool { return true },
		Now:            func() time.Time { return fixtureTime },
		Timeout:        10 * time.Second,
	}
}

func fixtureEnv(t *testing.T) *env {
	return &env{root: fixtureRoot, packageManager: "dpkg", run: fakeRunner(t), privileged: func() bool { return true }}
}

func encode(t *testing.T, r *Runtime) []byte {
	t.Helper()
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}

// TestGolden compares the complete runtime object of the fixture system with
// the golden file and proves the output is deterministic.
func TestGolden(t *testing.T) {
	first := encode(t, Collect(context.Background(), fixtureOptions(t)))
	second := encode(t, Collect(context.Background(), fixtureOptions(t)))
	if !bytes.Equal(first, second) {
		t.Fatal("two runs on the same system produced different JSON")
	}

	golden := filepath.Join("testdata", "runtime.golden.json")
	if *update {
		if err := os.WriteFile(golden, first, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(first, want) {
		t.Errorf("runtime JSON differs from %s (run go test -update after checking the change):\n%s", golden, first)
	}
}

func TestDecodeAddrPort(t *testing.T) {
	tests := []struct {
		in       string
		wantAddr string
		wantPort int
	}{
		{"00000000:0016", "0.0.0.0", 22},
		{"0100007F:0277", "127.0.0.1", 631},
		{"3500007F:0035", "127.0.0.53", 53},
		{"0F02000A:A1B2", "10.0.2.15", 41394},
		{"00000000000000000000000000000000:0016", "::", 22},
		{"00000000000000000000000001000000:0277", "::1", 631},
		{"0000000000000000FFFF00000100007F:2328", "::ffff:127.0.0.1", 9000},
		{"B80D0120000000000000000001000000:01BB", "2001:db8::1", 443},
		{"000080FE00000000FF005450B6AD1DFE:0222", "fe80::5054:ff:fe1d:adb6", 546},
	}
	for _, tt := range tests {
		addr, port, err := decodeAddrPort(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if addr.String() != tt.wantAddr || port != tt.wantPort {
			t.Errorf("%s: got %s:%d, want %s:%d", tt.in, addr, port, tt.wantAddr, tt.wantPort)
		}
	}
	for _, bad := range []string{"", "0100007F", "XYZ:0016", "0100007F:XYZ", "01007F:0016"} {
		if _, _, err := decodeAddrPort(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestParseProcNet(t *testing.T) {
	tcp, err := os.ReadFile(fixtureRoot + "/proc/1/net/tcp")
	if err != nil {
		t.Fatal(err)
	}
	socks, err := parseProcNet("tcp", string(tcp))
	if err != nil {
		t.Fatal(err)
	}
	want := []socket{
		{"tcp", "0.0.0.0", 22, 1001},
		{"tcp", "0.0.0.0", 80, 2001},
		{"tcp", "127.0.0.53", 53, 4002},
		{"tcp", "0.0.0.0", 111, 6001},
	}
	if !reflect.DeepEqual(socks, want) {
		t.Errorf("tcp: got %+v, want %+v (established connections must be skipped)", socks, want)
	}

	udp, err := os.ReadFile(fixtureRoot + "/proc/1/net/udp")
	if err != nil {
		t.Fatal(err)
	}
	socks, err = parseProcNet("udp", string(udp))
	if err != nil {
		t.Fatal(err)
	}
	want = []socket{
		{"udp", "127.0.0.53", 53, 4001},
		{"udp", "0.0.0.0", 68, 4004},
	}
	if !reflect.DeepEqual(socks, want) {
		t.Errorf("udp: got %+v, want %+v (connected sockets must be skipped)", socks, want)
	}
}

func TestReadProcModulesAndPaths(t *testing.T) {
	mods, err := readProcModules(fixtureRoot + "/proc/modules")
	if err != nil {
		t.Fatal(err)
	}
	dep, err := readModulesDep(fixtureRoot + "/lib/modules/6.8.0-124-generic/modules.dep")
	if err != nil {
		t.Fatal(err)
	}
	if len(dep) != 7 {
		t.Errorf("modules.dep: got %d paths, want 7", len(dep))
	}
	paths := modulePathsByName(dep)
	got := map[string]string{}
	for _, m := range mods {
		got[m.Name] = paths[m.Name]
	}
	want := map[string]string{
		"ath9k":         "kernel/drivers/net/wireless/ath/ath9k/ath9k.ko.zst",
		"nf_tables":     "kernel/net/netfilter/nf_tables.ko.zst",
		"out_of_tree":   "",
		"snd_hda_intel": "kernel/sound/pci/hda/snd-hda-intel.ko.zst",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if mods[0].Name != "ath9k" || mods[len(mods)-1].Name != "snd_hda_intel" {
		t.Errorf("modules not sorted: %v", mods)
	}
	if p := modulePathsByName([]string{"a/x.ko", "b/x.ko.xz"}); p["x"] != "" {
		t.Errorf("ambiguous module name must not get a path, got %q", p["x"])
	}
}

func TestModulesBuiltin(t *testing.T) {
	lines, err := readLines(fixtureRoot + "/lib/modules/6.8.0-124-generic/modules.builtin")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"kernel/fs/ext4/ext4.ko", "kernel/crypto/sha256_generic.ko"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("got %v, want %v", lines, want)
	}
}

func TestModuleIndexHash(t *testing.T) {
	// The backend recomputes this hash; both must use the same formula.
	got := ModuleIndexHash("6.8.0-1-generic", []string{"a.ko", "b.ko"}, []string{"c.ko"})
	want := "sha256:" + sha256Hex("6.8.0-1-generic\na.ko\nb.ko\nc.ko")
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestBlacklist(t *testing.T) {
	got, err := readBlacklist(fixtureEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []BlacklistedModule{
		{Name: "cramfs", InstallCommand: "/bin/false"},
		{Name: "evbug"},
		{Name: "freevxfs", InstallCommand: "/usr/bin/true"},
		{Name: "kept_by_override"},
		{Name: "pcspkr"},
		{Name: "udf", InstallCommand: "/bin/false"},
	}
	// "blacklist snd-pcsp # comment" has three fields and is not a valid
	// directive; hidden_by_override is replaced by /etc; usb-storage has a
	// real install command; README is not a .conf file.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseModprobeConfMerges(t *testing.T) {
	m := map[string]*BlacklistedModule{}
	parseModprobeConf("blacklist foo-bar\ninstall foo_bar /bin/true\n# blacklist commented\n", m)
	if len(m) != 1 || m["foo_bar"].InstallCommand != "/bin/true" {
		t.Errorf("got %+v", m)
	}
}

func TestInstalledKernels(t *testing.T) {
	got, err := readInstalledKernels(fixtureRoot + "/var/lib/dpkg/status")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"6.8.0-121-generic", "6.8.0-124-generic"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for pkg, want := range map[string]string{
		"linux-image-6.1.0-18-amd64":            "6.1.0-18-amd64",
		"linux-image-6.1.0-18-amd64-unsigned":   "6.1.0-18-amd64",
		"linux-image-unsigned-6.8.0-1-generic":  "6.8.0-1-generic",
		"linux-image-generic":                   "",
		"linux-image-amd64":                     "",
		"linux-image-6.1.0-18-amd64-dbg":        "",
		"linux-image-unsigned-6.8.0-1-g-dbgsym": "",
		"linux-headers-6.8.0-1-generic":         "",
	} {
		if got, _ := kernelRelease(pkg); got != want {
			t.Errorf("kernelRelease(%q) = %q, want %q", pkg, got, want)
		}
	}
}

func TestMappedFiles(t *testing.T) {
	files, err := readMappedFiles(fixtureRoot + "/proc/200/maps")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/usr/sbin/nginx": true,
		"/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)": true,
		"/usr/lib/x86_64-linux-gnu/libc.so.6":             true,
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2":  true,
	}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("got %v, want %v", files, want)
	}
	if p, ok := mappedPath("7f00-7f01 r-xp 00000000 fd:01 42      /opt/my app/lib.so"); !ok || p != "/opt/my app/lib.so" {
		t.Errorf("path with spaces: got %q", p)
	}
	for _, line := range []string{
		"7f00-7f01 rw-p 00000000 00:00 0 ",
		"7f00-7f01 rw-p 00000000 00:00 0      [heap]",
		"7f00-7f01 rw-s 00000000 00:01 0      /dev/zero (deleted)",
		"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0    [vsyscall]",
	} {
		if p, ok := mappedPath(line); ok {
			t.Errorf("%q: unexpected path %q", line, p)
		}
	}
}

func TestDpkgIndex(t *testing.T) {
	e := fixtureEnv(t)
	idx, err := e.dpkgIndex()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path, want string
	}{
		{"/usr/sbin/sshd", "openssh-server"},
		{"/sbin/sshd", "openssh-server"},                                // merged /usr, listed with /usr
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "libc6"},                // merged /usr, listed without /usr
		{"/usr/lib64/ld-linux-x86-64.so.2", "libc6"},                    // lib64
		{"/usr/share/doc/libc6/copyright", "libc6"},                     // same package, two architectures
		{"/usr/share/doc/shared-file", ""},                              // two packages: ambiguous
		{"/etc/systemd/system/sshd.service", "openssh-server"},          // symlink, one level
		{"/usr/bin/foo", "bar"},                                         // diverted path, diverter lists it
		{"/usr/bin/foo.distrib", "foo"},                                 // diversion target
		{"/usr/sbin/local", ""},                                         // local diversion
		{"/usr/bin/python3.12", "python3.12"},                           // owned on the host
		{"/usr/share/../sbin/nginx", "nginx-core"},                      // cleaned
		{"relative/path", ""},                                           // not absolute
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "libssl3t64"},         // :arch suffix removed
		{"/lib/systemd/system/ssh.service", "openssh-server"},           // listed without /usr
		{"/usr/lib/systemd/system/ssh.service", "openssh-server"},       // looked up with /usr
		{"/usr/lib/systemd/system/getty@.service", "systemd"},           // template unit
		{"/usr/lib/systemd/system/does-not-exist.service", ""},          // unknown
		{"/usr/lib/systemd/system/systemd-resolved.service", "systemd"}, // plain
	}
	for _, tt := range tests {
		got, ok := idx.Lookup(tt.path)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("Lookup(%q) = %q, %v; want %q", tt.path, got, ok, tt.want)
		}
	}
	if again, _ := e.dpkgIndex(); again != idx {
		t.Error("dpkg index must be built only once per run")
	}
}

func TestDpkgIndexOnlyForDpkg(t *testing.T) {
	e := fixtureEnv(t)
	e.packageManager = "rpm"
	if _, err := e.dpkgIndex(); err == nil {
		t.Error("expected an error for rpm systems")
	}
}

func TestParseListUnitsAndShow(t *testing.T) {
	out, _ := os.ReadFile("testdata/systemctl/list-units.txt")
	units := parseListUnits(string(out))
	want := []string{"nginx.service", "ssh.service", "systemd-resolved.service", "failed-thing.service", "getty@tty1.service", "legacy.service"}
	if !reflect.DeepEqual(units, want) {
		t.Errorf("got %v, want %v", units, want)
	}
	show, _ := os.ReadFile("testdata/systemctl/show.txt")
	blocks := parseShow(string(show))
	if len(blocks) != 6 {
		t.Fatalf("got %d blocks, want 6", len(blocks))
	}
	if blocks[1]["Id"] != "ssh.service" || blocks[1]["FragmentPath"] != "/etc/systemd/system/sshd.service" {
		t.Errorf("unexpected block %v", blocks[1])
	}
	if v, ok := blocks[5]["UnitFileState"]; !ok || v != "" {
		t.Errorf("empty value not parsed: %v", blocks[5])
	}
}

func TestServicesBatching(t *testing.T) {
	var list strings.Builder
	var show strings.Builder
	for i := 0; i < 250; i++ {
		u := "unit-" + strconv.Itoa(i) + ".service"
		list.WriteString(u + " loaded active running X\n")
		show.WriteString("Id=" + u + "\nActiveState=active\nSubState=running\n\n")
	}
	calls := 0
	e := fixtureEnv(t)
	e.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if args[0] == "list-units" {
			return []byte(list.String()), nil
		}
		calls++
		if n := len(args) - 3; n > showBatchSize {
			t.Errorf("batch of %d units", n)
		}
		var out []string
		for _, u := range args[3:] {
			out = append(out, "Id="+u+"\nActiveState=active\nSubState=running\n")
		}
		return []byte(strings.Join(out, "\n")), nil
	}
	r := &Runtime{}
	res := collectServices(context.Background(), e)
	res.apply(r)
	if calls != 3 || len(*r.Services) != 250 {
		t.Errorf("calls=%d services=%d, want 3 and 250", calls, len(*r.Services))
	}
}

func TestUnitFromCgroup(t *testing.T) {
	tests := map[string]string{
		"0::/system.slice/ssh.service\n":                   "ssh.service",
		"0::/user.slice/user-1000.slice/session-3.scope\n": "session-3.scope",
		"0::/system.slice/docker-abc.scope\n":              "docker-abc.scope",
		"0::/\n":                                           "",
		"0::/init.scope\n":                                 "init.scope",
		"12:pids:/system.slice/x.service\n1:name=systemd:/system.slice/cron.service\n0::/\n": "cron.service",
		"0::/system.slice/foo.service/payload\n":                                             "foo.service",
	}
	for in, want := range tests {
		if got := unitFromCgroup(in); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasProcCaps(t *testing.T) {
	tests := map[string]bool{
		"Name:\tx\nCapEff:\t000001ffffffffff\n": true,  // root
		"CapEff:\t0000000000080004\n":           true,  // CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH
		"CapEff:\t0000000000080000\n":           false, // only CAP_SYS_PTRACE
		"CapEff:\t0000000000000000\n":           false,
		"Name:\tx\n":                            false,
	}
	for in, want := range tests {
		if got := hasProcCaps(in); got != want {
			t.Errorf("hasProcCaps(%q) = %v, want %v", in, got, want)
		}
	}
}

// A failing collector must lead to an omitted field plus an errors entry,
// never to an empty list.
func TestFailingCollectorsAreOmitted(t *testing.T) {
	opts := fixtureOptions(t)
	opts.Privileged = func() bool { return false }
	opts.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemd-detect-virt" {
			return []byte("\n"), errors.New("exit status 2")
		}
		return nil, exec.ErrNotFound
	}
	r := Collect(context.Background(), opts)
	b, _ := r.Encode()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"listeners", "packagesInUse", "services", "virtualization"} {
		if _, ok := obj[field]; ok {
			t.Errorf("%s must be omitted, got %s", field, obj[field])
		}
	}
	for _, field := range []string{"kernel", "packageInfo"} {
		if _, ok := obj[field]; !ok {
			t.Errorf("%s should still be collected", field)
		}
	}
	want := []CollectorError{
		{Collector: "listeners", Error: "insufficient privileges"},
		{Collector: "packagesInUse", Error: "insufficient privileges"},
		{Collector: "services", Error: "systemctl list-units: command not found"},
		{Collector: "virtualization", Error: "systemd-detect-virt: exit status 2"},
	}
	if !reflect.DeepEqual(r.Errors, want) {
		t.Errorf("errors: got %+v\nwant %+v", r.Errors, want)
	}
}

func TestVirtualizationNone(t *testing.T) {
	e := fixtureEnv(t)
	e.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("none\n"), &ExitStatusError{Code: 1}
	}
	r := &Runtime{}
	res := collectVirtualization(context.Background(), e)
	if res.apply == nil {
		t.Fatalf("expected a result, got errors %v", res.errs)
	}
	res.apply(r)
	if r.Virtualization != "none" {
		t.Errorf("got %q", r.Virtualization)
	}
}

func TestMissingKernelFiles(t *testing.T) {
	// Missing modules.dep: loaded modules without paths, no module index.
	root := t.TempDir()
	mustWrite(t, root+"/proc/sys/kernel/osrelease", "6.0.0-1\n")
	mustWrite(t, root+"/proc/modules", "foo 1 0 - Live 0x0\n")
	r := Collect(context.Background(), Options{
		Root: root, PackageManager: "dpkg", Collectors: []string{CollectorKernel},
		Now: func() time.Time { return fixtureTime },
	})
	if r.Kernel == nil {
		t.Fatalf("kernel missing: %+v", r.Errors)
	}
	if r.Kernel.ModuleIndex != nil || r.Kernel.ModulesDisabled != nil || r.Kernel.InstalledKernels != nil {
		t.Errorf("unknown fields must be omitted: %+v", r.Kernel)
	}
	if r.Kernel.LoadedModules == nil || (*r.Kernel.LoadedModules)[0].Path != "" {
		t.Errorf("loaded modules: %+v", r.Kernel.LoadedModules)
	}
	if r.Kernel.BlacklistedModules == nil || len(*r.Kernel.BlacklistedModules) != 0 {
		t.Errorf("no modprobe.d directories means an empty blacklist: %+v", r.Kernel.BlacklistedModules)
	}
	if r.Kernel.RebootRequired == nil || *r.Kernel.RebootRequired || r.Kernel.RebootRequiredPackages != nil {
		t.Errorf("reboot: %v %v", r.Kernel.RebootRequired, r.Kernel.RebootRequiredPackages)
	}
	var fields []string
	for _, e := range r.Errors {
		fields = append(fields, strings.SplitN(e.Error, ":", 2)[0])
	}
	if want := []string{"installedKernels", "moduleIndex", "modulesDisabled"}; !reflect.DeepEqual(fields, want) {
		t.Errorf("errors: got %v, want %v", fields, want)
	}
}

func TestTimeout(t *testing.T) {
	opts := fixtureOptions(t)
	opts.Timeout = 200 * time.Millisecond
	inner := opts.Run
	opts.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			<-ctx.Done() // hangs until the budget is used up
			return nil, ctx.Err()
		}
		return inner(ctx, name, args...)
	}
	start := time.Now()
	r := Collect(context.Background(), opts)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("collection took %v", d)
	}
	if r.Services != nil {
		t.Error("services must be omitted after a timeout")
	}
	if r.Kernel == nil || r.Listeners == nil || r.Virtualization != "kvm" {
		t.Error("other collectors must not be affected")
	}
	found := false
	for _, e := range r.Errors {
		if e.Collector == "services" && strings.HasPrefix(e.Error, "timeout") {
			found = true
		}
	}
	if !found {
		t.Errorf("no timeout error for services: %+v", r.Errors)
	}
}

func TestHangingCollectorIsAbandoned(t *testing.T) {
	opts := fixtureOptions(t)
	opts.Collectors = []string{CollectorVirtualization}
	opts.Timeout = 100 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	opts.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		<-release // ignores the context entirely
		return []byte("kvm"), nil
	}
	r := Collect(context.Background(), opts)
	if r.Virtualization != "" || len(r.Errors) != 1 || !strings.HasPrefix(r.Errors[0].Error, "timeout") {
		t.Errorf("got virtualization=%q errors=%+v", r.Virtualization, r.Errors)
	}
}

func TestSelectedCollectors(t *testing.T) {
	opts := fixtureOptions(t)
	opts.Collectors = []string{CollectorServices}
	r := Collect(context.Background(), opts)
	if r.Kernel != nil || r.Listeners != nil || r.PackagesInUse != nil || r.PackageInfo != nil || r.Virtualization != "" {
		t.Error("collectors that are not selected must be omitted")
	}
	if r.Services == nil || r.Errors != nil {
		t.Errorf("services: %v errors: %v", r.Services, r.Errors)
	}

	opts.Collectors = []string{}
	r = Collect(context.Background(), opts)
	b, _ := r.Encode()
	if string(b) != `{"schemaVersion":1,"collectedAt":"2026-11-05T10:00:03Z"}` {
		t.Errorf("got %s", b)
	}
}

func TestNonDpkgSystem(t *testing.T) {
	opts := fixtureOptions(t)
	opts.PackageManager = "rpm"
	r := Collect(context.Background(), opts)
	if r.PackagesInUse != nil || r.PackageInfo != nil {
		t.Error("packagesInUse and packageInfo need the dpkg database")
	}
	for _, l := range *r.Listeners {
		if l.Package != "" {
			t.Errorf("listener %+v must not have a package", l)
		}
	}
	for _, s := range *r.Services {
		if s.Package != "" {
			t.Errorf("service %+v must not have a package", s)
		}
	}
	if r.Kernel.InstalledKernels != nil || r.Kernel.RebootRequired != nil {
		t.Error("dpkg-only kernel facts must be omitted")
	}
}

func TestTruncation(t *testing.T) {
	defer func(l, p, s, n int) { maxListeners, maxPackagesInUse, maxServices, maxProcessesPerPkg = l, p, s, n }(
		maxListeners, maxPackagesInUse, maxServices, maxProcessesPerPkg)
	maxListeners, maxPackagesInUse, maxServices, maxProcessesPerPkg = 2, 100, 3, 1
	r := Collect(context.Background(), fixtureOptions(t))
	if len(*r.Listeners) != 2 || len(*r.Services) != 3 {
		t.Errorf("caps not applied: %d listeners, %d services", len(*r.Listeners), len(*r.Services))
	}
	// libc is used by several processes, so maxProcessesPerPkg=1 cuts it.
	if want := []string{"listeners", "packagesInUse", "services"}; !reflect.DeepEqual(r.Truncated, want) {
		t.Errorf("truncated: got %v, want %v", r.Truncated, want)
	}
	// Caps are applied after sorting: the first entries are kept.
	if (*r.Services)[0].Unit != "failed-thing.service" {
		t.Errorf("unexpected first service %v", (*r.Services)[0])
	}
}

func TestEncodeSizeLimit(t *testing.T) {
	defer func(n int) { maxRuntimeBytes = n }(maxRuntimeBytes)
	full := Collect(context.Background(), fixtureOptions(t))
	b, _ := json.Marshal(full)
	withoutIndex := Collect(context.Background(), fixtureOptions(t))
	withoutIndex.Kernel.ModuleIndex.Available, withoutIndex.Kernel.ModuleIndex.Builtin = nil, nil
	bNoIdx, _ := json.Marshal(withoutIndex)

	// Just below the full size: the index lists are dropped, the hash stays.
	maxRuntimeBytes = len(b) - 1
	r := Collect(context.Background(), fixtureOptions(t))
	if _, err := r.Encode(); err != nil {
		t.Fatal(err)
	}
	if r.Kernel.ModuleIndex.Available != nil || r.Kernel.ModuleIndex.Hash == "" || r.PackagesInUse == nil {
		t.Errorf("expected index lists dropped, hash and packagesInUse kept")
	}
	if r.FullModuleIndexHash() != "" {
		t.Error("no state must be stored when the index was not sent")
	}

	// Still too large without the index: packageInfo goes first, with an error.
	maxRuntimeBytes = len(bNoIdx) - 1
	r = Collect(context.Background(), fixtureOptions(t))
	if _, err := r.Encode(); err != nil {
		t.Fatal(err)
	}
	if r.PackageInfo != nil || r.PackagesInUse == nil {
		t.Error("packageInfo should be omitted, packagesInUse kept")
	}
	if want := []CollectorError{{Collector: "packageInfo", Error: "omitted: runtime object exceeds the size limit"}}; !reflect.DeepEqual(r.Errors, want) {
		t.Errorf("errors: got %+v, want %+v", r.Errors, want)
	}

	// Still too large without packageInfo: packagesInUse goes as well.
	withoutInfo := Collect(context.Background(), fixtureOptions(t))
	withoutInfo.Kernel.ModuleIndex.Available, withoutInfo.Kernel.ModuleIndex.Builtin = nil, nil
	withoutInfo.PackageInfo = nil
	bNoInfo, _ := json.Marshal(withoutInfo)
	maxRuntimeBytes = len(bNoInfo) - 1
	r = Collect(context.Background(), fixtureOptions(t))
	if _, err := r.Encode(); err != nil {
		t.Fatal(err)
	}
	if r.PackageInfo != nil || r.PackagesInUse != nil {
		t.Error("packageInfo and packagesInUse should be omitted")
	}
	if len(r.Errors) != 2 || r.Errors[0].Collector != "packageInfo" || r.Errors[1].Collector != "packagesInUse" {
		t.Errorf("errors: got %+v", r.Errors)
	}

	// Far too large: Encode fails, the caller omits runtime entirely.
	maxRuntimeBytes = 100
	if _, err := Collect(context.Background(), fixtureOptions(t)).Encode(); err == nil {
		t.Error("expected an error")
	}
}

func TestModuleIndexState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "sub", "module-index.sha256")
	now := time.Now()
	collect := func() *Runtime {
		r := Collect(context.Background(), fixtureOptions(t))
		ApplyModuleIndexState(r, state, now)
		return r
	}

	// First run: no state file, full index.
	r := collect()
	if r.Kernel.ModuleIndex.Available == nil || r.FullModuleIndexHash() == "" {
		t.Fatal("first run must send the full index")
	}
	hash := r.FullModuleIndexHash()

	// The report failed: no state is written, the next run sends it again.
	r = collect()
	if r.Kernel.ModuleIndex.Available == nil {
		t.Fatal("without an accepted report the full index must be sent again")
	}

	// Accepted: the second run sends only the hash.
	if err := SaveModuleIndexState(state, hash); err != nil {
		t.Fatal(err)
	}
	r = collect()
	if r.Kernel.ModuleIndex.Available != nil || r.Kernel.ModuleIndex.Builtin != nil || r.Kernel.ModuleIndex.Hash != hash {
		t.Fatal("second run must send only the hash")
	}
	if r.FullModuleIndexHash() != "" {
		t.Error("hash-only report must not update the state file")
	}
	b, _ := json.Marshal(r.Kernel.ModuleIndex)
	if string(b) != `{"hash":"`+hash+`"}` {
		t.Errorf("hash-only form: %s", b)
	}

	// After 24 hours the full index is sent again.
	old := now.Add(-25 * time.Hour)
	if err := os.Chtimes(state, old, old); err != nil {
		t.Fatal(err)
	}
	if r = collect(); r.Kernel.ModuleIndex.Available == nil {
		t.Error("full index expected after 24 hours")
	}

	// A different hash (e.g. new kernel modules) sends the full index.
	if err := SaveModuleIndexState(state, "sha256:other"); err != nil {
		t.Fatal(err)
	}
	if r = collect(); r.Kernel.ModuleIndex.Available == nil {
		t.Error("full index expected after a hash change")
	}

	if err := SaveModuleIndexState(state, ""); err != nil {
		t.Error(err)
	}
	if data, _ := os.ReadFile(state); strings.TrimSpace(string(data)) != "sha256:other" {
		t.Error("an empty hash must not touch the state file")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// With socket activation PID 1 holds the listening socket too; the service
// that inherited it must be reported, PID 1 only when nobody else holds it.
func TestSocketActivationOwner(t *testing.T) {
	r := Collect(context.Background(), fixtureOptions(t))
	got := map[int]string{}
	for _, l := range *r.Listeners {
		if l.Protocol == "tcp" && l.Address == "0.0.0.0" {
			got[l.Port] = l.Process + "/" + l.Package
		}
	}
	if got[22] != "sshd/openssh-server" {
		t.Errorf("port 22: got %q, want sshd/openssh-server", got[22])
	}
	if got[111] != "systemd/systemd" {
		t.Errorf("port 111: got %q, want systemd/systemd", got[111])
	}
}

// Processes with another root (containers) see their own filesystem; their
// paths must not be resolved against the host's dpkg database.
func TestContainerPathsNotResolved(t *testing.T) {
	r := Collect(context.Background(), fixtureOptions(t))
	for _, l := range *r.Listeners {
		if l.Process == "python3" && l.Package != "" {
			t.Errorf("container listener got host package %q", l.Package)
		}
	}
	for _, p := range *r.PackagesInUse {
		if p.Package == "python3.12" {
			t.Error("host package python3.12 attributed to a container process")
		}
		for _, proc := range p.Processes {
			if proc == "python3" {
				t.Errorf("container process listed for host package %s", p.Package)
			}
		}
	}
	e := fixtureEnv(t)
	if !e.hostRoot(100) || e.hostRoot(300) || e.hostRoot(99999) {
		t.Error("hostRoot: want true for pid 100, false for the container and unknown pids")
	}
}
