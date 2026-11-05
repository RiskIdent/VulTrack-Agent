package runtimefacts

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Capabilities needed to read other processes' /proc entries as non-root:
// CAP_DAC_READ_SEARCH to list /proc/<pid>/fd, CAP_SYS_PTRACE to read maps,
// exe, fd and ns links.
const (
	capDacReadSearch = 2
	capSysPtrace     = 19
)

// HasProcAccess reports whether the agent can read the /proc entries of all
// processes. It checks the effective capabilities of the agent process, which
// covers both root and a service user with the required capabilities.
func HasProcAccess() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return hasProcCaps(string(data))
}

// hasProcCaps parses the CapEff line of /proc/<pid>/status.
func hasProcCaps(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		need := uint64(1)<<capDacReadSearch | uint64(1)<<capSysPtrace
		return v&need == need
	}
	return false
}

// listPIDs returns the numeric entries of /proc in ascending order.
func listPIDs(e *env) ([]int, error) {
	entries, err := os.ReadDir(e.path("/proc"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

// procPath returns /proc/<pid>/<name> below the root.
func procPath(e *env, pid int, name string) string {
	return e.path("/proc/" + strconv.Itoa(pid) + "/" + name)
}

// processGone reports whether err means the process exited while being read.
func processGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// readComm returns /proc/<pid>/comm without the trailing newline.
func readComm(e *env, pid int) (string, error) {
	b, err := os.ReadFile(procPath(e, pid, "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

// readExe returns the target of /proc/<pid>/exe.
func readExe(e *env, pid int) (string, error) {
	return os.Readlink(procPath(e, pid, "exe"))
}

// unitFromCgroup returns the systemd unit of a process: the last path element
// ending in ".service" or ".scope" in /proc/<pid>/cgroup. The unified
// hierarchy ("0::") is preferred over the v1 "name=systemd" hierarchy.
func unitFromCgroup(content string) string {
	var unified, named string
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			unified = parts[2]
		case parts[1] == "name=systemd":
			named = parts[2]
		}
	}
	path := unified
	if path == "" || path == "/" {
		path = named
	}
	unit := ""
	for _, elem := range strings.Split(path, "/") {
		if strings.HasSuffix(elem, ".service") || strings.HasSuffix(elem, ".scope") {
			unit = elem
		}
	}
	return unit
}

// errResult is a collector result that only records an error.
func errResult(category, msg string) collectorResult {
	return collectorResult{errs: []CollectorError{{Collector: category, Error: msg}}}
}

// timeoutResult is returned by collectors that notice the deadline.
func timeoutResult(category string, ctx context.Context) collectorResult {
	return errResult(category, "timeout: "+ctx.Err().Error())
}
