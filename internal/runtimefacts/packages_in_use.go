package runtimefacts

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
)

// PackageInUse is a package with files mapped by running processes.
type PackageInUse struct {
	Package        string   `json:"package"`
	Processes      []string `json:"processes"`
	StaleProcesses []string `json:"staleProcesses,omitempty"`
}

const deletedSuffix = " (deleted)"

func collectPackagesInUse(ctx context.Context, e *env) collectorResult {
	if !e.privileged() {
		return errResult(categoryPackagesInUse, errInsufficientPriv)
	}
	idx, err := e.dpkgIndex()
	if err != nil {
		return errResult(categoryPackagesInUse, "package lookup unavailable: "+err.Error())
	}
	pids, err := listPIDs(e)
	if err != nil {
		return errResult(categoryPackagesInUse, err.Error())
	}

	type usage struct{ procs, stale map[string]bool }
	byPkg := map[string]*usage{}
	lookup := map[string]string{} // path → package ("" = none)
	pkgOf := func(p string) string {
		if pkg, ok := lookup[p]; ok {
			return pkg
		}
		pkg, _ := idx.Lookup(p)
		lookup[p] = pkg
		return pkg
	}

	for _, pid := range pids {
		if ctx.Err() != nil {
			return timeoutResult(categoryPackagesInUse, ctx)
		}
		files, err := readMappedFiles(procPath(e, pid, "maps"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return errResult(categoryPackagesInUse, fmt.Sprintf("pid %d: %v", pid, err))
		}
		if len(files) == 0 {
			continue // kernel thread (or a process that just exited)
		}
		// A process with another root (a container) maps files of its own
		// filesystem; resolving them against the host's dpkg would be a guess.
		if !e.hostRoot(pid) {
			continue
		}
		exe, err := readExe(e, pid)
		if err != nil && !processGone(err) {
			return errResult(categoryPackagesInUse, fmt.Sprintf("pid %d: %v", pid, err))
		}
		if exe != "" {
			files[exe] = true
		}
		comm, err := readComm(e, pid)
		if err != nil {
			if processGone(err) {
				continue
			}
			return errResult(categoryPackagesInUse, fmt.Sprintf("pid %d: %v", pid, err))
		}
		if comm == "" {
			continue
		}
		for f := range files {
			p, stale := strings.CutSuffix(f, deletedSuffix)
			pkg := pkgOf(p)
			if pkg == "" {
				continue
			}
			u, ok := byPkg[pkg]
			if !ok {
				u = &usage{procs: map[string]bool{}, stale: map[string]bool{}}
				byPkg[pkg] = u
			}
			u.procs[comm] = true
			if stale {
				u.stale[comm] = true
			}
		}
	}

	truncated := false
	limit := func(set map[string]bool) []string {
		out := make([]string, 0, len(set))
		for name := range set {
			out = append(out, name)
		}
		sort.Strings(out)
		if len(out) > maxProcessesPerPkg {
			out = out[:maxProcessesPerPkg]
			truncated = true
		}
		return out
	}
	result := make([]PackageInUse, 0, len(byPkg))
	for pkg, u := range byPkg {
		p := PackageInUse{Package: pkg, Processes: limit(u.procs)}
		if len(u.stale) > 0 {
			p.StaleProcesses = limit(u.stale)
		}
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Package < result[j].Package })
	if len(result) > maxPackagesInUse {
		result = result[:maxPackagesInUse]
		truncated = true
	}

	res := collectorResult{apply: func(r *Runtime) { r.PackagesInUse = &result }}
	if truncated {
		res.truncated = []string{categoryPackagesInUse}
	}
	return res
}

// readMappedFiles returns the distinct file paths of the file-backed mappings
// in a /proc/<pid>/maps file, including a " (deleted)" suffix if present.
func readMappedFiles(file string) (map[string]bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	files := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if p, ok := mappedPath(sc.Text()); ok {
			files[p] = true
		}
	}
	return files, sc.Err()
}

// mappedPath extracts the path of a file-backed mapping from one maps line:
// "address perms offset dev inode   pathname". Anonymous and pseudo mappings
// ([heap], [stack], inode 0) are skipped.
func mappedPath(line string) (string, bool) {
	rest := line
	var inode string
	for i := 0; i < 5; i++ {
		rest = strings.TrimLeft(rest, " ")
		field, r, ok := strings.Cut(rest, " ")
		if !ok {
			return "", false
		}
		if i == 4 {
			inode = field
		}
		rest = r
	}
	p := strings.TrimLeft(rest, " ")
	if inode == "0" || !strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}
