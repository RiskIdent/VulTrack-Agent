package runtimefacts

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ambiguous marks a path that is owned by more than one package.
const ambiguous = "\x00"

// dpkgIndex maps file paths to the dpkg package that owns them. It is built
// from /var/lib/dpkg/info/*.list at most once per report and is not kept
// between reports.
type dpkgIndex struct {
	e *env
	// owners maps a path to its package (or ambiguous).
	owners map[string]string
	// diverted maps a diverted original path to the package that now owns
	// the file at that path ("" when unknown, e.g. a local diversion).
	diverted map[string]string
	// divertedTo maps a diversion target to the package whose file was moved
	// there ("" when unknown).
	divertedTo map[string]string
	// merged lists the top-level directories that are symlinks into /usr.
	merged map[string]bool
	// files maps a package name (without architecture) to the paths of all
	// its file lists, in list order. A package with an (empty) list has a
	// non-nil entry.
	files map[string][]string
	// diversions maps a diverted original path to its diversion.
	diversions map[string]diversion
}

type diversion struct {
	from, to, by string
}

// buildDpkgIndex reads the dpkg file lists and diversions.
func buildDpkgIndex(e *env) (*dpkgIndex, error) {
	idx := &dpkgIndex{
		e:          e,
		owners:     make(map[string]string, 1<<17),
		diverted:   map[string]string{},
		divertedTo: map[string]string{},
		merged:     map[string]bool{},
		files:      map[string][]string{},
		diversions: map[string]diversion{},
	}

	divs, err := readDiversions(e.path("/var/lib/dpkg/diversions"))
	if err != nil {
		return nil, err
	}
	// listers records which packages list each diverted original path.
	listers := map[string][]string{}
	for _, d := range divs {
		listers[d.from] = nil
		idx.diversions[d.from] = d
	}

	lists, err := filepath.Glob(e.path("/var/lib/dpkg/info") + "/*.list")
	if err != nil {
		return nil, err
	}
	if len(lists) == 0 {
		return nil, errors.New("no dpkg file lists found in /var/lib/dpkg/info")
	}
	for _, list := range lists {
		pkg := dpkgPackageName(filepath.Base(list))
		if err := idx.readList(list, pkg, listers); err != nil {
			return nil, err
		}
	}

	for _, d := range divs {
		// The file at the original path belongs to the diverting package only
		// if that package lists it; local diversions (":") have no package.
		owner := ""
		others := map[string]bool{}
		for _, p := range listers[d.from] {
			if p == d.by {
				owner = d.by
			} else {
				others[p] = true
			}
		}
		idx.diverted[d.from] = owner
		// The file at the diversion target is the one the other package
		// shipped at the original path. Only a single candidate is exact.
		to := ""
		if len(others) == 1 {
			for p := range others {
				to = p
			}
		}
		idx.divertedTo[d.to] = to
	}

	for _, dir := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		target, err := os.Readlink(e.path("/" + dir))
		if err != nil {
			continue
		}
		if t := strings.TrimPrefix(target, "/"); t == "usr/"+dir {
			idx.merged[dir] = true
		}
	}
	return idx, nil
}

// dpkgPackageName turns "libssl3t64:amd64.list" into "libssl3t64".
func dpkgPackageName(file string) string {
	name := strings.TrimSuffix(file, ".list")
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	return name
}

func (idx *dpkgIndex) readList(file, pkg string, listers map[string][]string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	files := idx.files[pkg]
	if files == nil {
		files = []string{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		p := sc.Text()
		if p == "" || p == "/." {
			continue
		}
		files = append(files, p)
		if l, ok := listers[p]; ok {
			listers[p] = append(l, pkg)
		}
		if old, ok := idx.owners[p]; ok && old != pkg {
			idx.owners[p] = ambiguous
			continue
		}
		idx.owners[p] = pkg
	}
	idx.files[pkg] = files
	return sc.Err()
}

// readDiversions parses /var/lib/dpkg/diversions (groups of three lines:
// original path, diversion target, diverting package or ":" for local).
func readDiversions(file string) ([]diversion, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var divs []diversion
	for i := 0; i+2 < len(lines); i += 3 {
		by := lines[i+2]
		if by == ":" {
			by = ""
		}
		divs = append(divs, diversion{from: lines[i], to: lines[i+1], by: by})
	}
	return divs, nil
}

// Lookup returns the package owning path, or false when it is unknown or
// ambiguous. The path is looked up as given and with the /usr prefix added or
// removed on merged-/usr systems; if that finds nothing, a symlink at path is
// resolved exactly one level.
func (idx *dpkgIndex) Lookup(p string) (string, bool) {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", false
	}
	p = path.Clean(p)
	if pkg, found := idx.lookupVariants(p); found {
		return pkg, pkg != ""
	}
	target, err := os.Readlink(idx.e.path(p))
	if err != nil {
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		target = path.Join(path.Dir(p), target)
	}
	pkg, _ := idx.lookupVariants(path.Clean(target))
	return pkg, pkg != ""
}

// lookupVariants looks p up as given and with merged-/usr variants. found is
// true when any variant is known; pkg is "" when the owner is not exact.
func (idx *dpkgIndex) lookupVariants(p string) (pkg string, found bool) {
	owners := map[string]bool{}
	for _, v := range idx.variants(p) {
		owner, ok := idx.lookupExact(v)
		if !ok {
			continue
		}
		found = true
		owners[owner] = true
	}
	if !found || len(owners) != 1 {
		return "", found
	}
	for o := range owners {
		pkg = o
	}
	if pkg == ambiguous {
		pkg = ""
	}
	return pkg, true
}

func (idx *dpkgIndex) lookupExact(p string) (string, bool) {
	if owner, ok := idx.diverted[p]; ok {
		return orAmbiguous(owner), true
	}
	if owner, ok := idx.divertedTo[p]; ok {
		if listed, ok := idx.owners[p]; ok && listed != owner {
			return ambiguous, true
		}
		return orAmbiguous(owner), true
	}
	owner, ok := idx.owners[p]
	return owner, ok
}

// orAmbiguous turns an unknown owner into the ambiguous marker so that it
// stops the lookup instead of being skipped.
func orAmbiguous(owner string) string {
	if owner == "" {
		return ambiguous
	}
	return owner
}

// variants returns p plus its merged-/usr counterpart, if any.
func (idx *dpkgIndex) variants(p string) []string {
	out := []string{p}
	rest := strings.TrimPrefix(p, "/")
	if strings.HasPrefix(rest, "usr/") {
		under := strings.TrimPrefix(rest, "usr/")
		top, _, _ := strings.Cut(under, "/")
		if idx.merged[top] {
			out = append(out, "/"+under)
		}
		return out
	}
	top, _, _ := strings.Cut(rest, "/")
	if idx.merged[top] {
		out = append(out, "/usr/"+rest)
	}
	return out
}
