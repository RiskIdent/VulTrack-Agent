package runtimefacts

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Listener is a listening TCP socket or a bound, unconnected UDP socket.
type Listener struct {
	Protocol  string `json:"protocol"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Process   string `json:"process,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Package   string `json:"package,omitempty"`
	Unit      string `json:"unit,omitempty"`
	HostNetns bool   `json:"hostNetns"`
}

// procNetFiles are the socket tables, named after the protocol they report.
var procNetFiles = []string{"tcp", "tcp6", "udp", "udp6"}

const (
	tcpListen = "0A"
	udpClose  = "07"
)

// socket is one relevant entry of a /proc/net socket table.
type socket struct {
	protocol string
	addr     string
	port     int
	inode    uint64
}

func collectListeners(ctx context.Context, e *env) collectorResult {
	if !e.privileged() {
		return errResult(categoryListeners, errInsufficientPriv)
	}

	pids, err := listPIDs(e)
	if err != nil {
		return errResult(categoryListeners, err.Error())
	}

	hostNs, err := os.Readlink(procPath(e, 1, "ns/net"))
	if err != nil {
		return errResult(categoryListeners, "network namespace of PID 1: "+err.Error())
	}

	// The processes of every network namespace (ascending), and the owner of
	// every socket inode (the lowest PID holding it).
	nsPIDs := map[string][]int{}
	var nsOrder []string
	owner := map[uint64]int{}
	for _, pid := range pids {
		if ctx.Err() != nil {
			return timeoutResult(categoryListeners, ctx)
		}
		ns, err := os.Readlink(procPath(e, pid, "ns/net"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return errResult(categoryListeners, fmt.Sprintf("pid %d: %v", pid, err))
		}
		if _, ok := nsPIDs[ns]; !ok {
			nsOrder = append(nsOrder, ns)
		}
		nsPIDs[ns] = append(nsPIDs[ns], pid)
		if err := scanSocketFDs(e, pid, owner); err != nil {
			return errResult(categoryListeners, fmt.Sprintf("pid %d: %v", pid, err))
		}
	}
	if _, ok := nsPIDs[hostNs]; !ok {
		return errResult(categoryListeners, "PID 1 not found in /proc")
	}

	idx, idxErr := e.dpkgIndex()
	var errs []CollectorError
	if idxErr != nil && e.packageManager == "dpkg" {
		errs = append(errs, CollectorError{Collector: categoryListeners, Error: "package lookup unavailable: " + idxErr.Error()})
	}

	type procInfo struct {
		comm, exe, pkg, unit string
		ok                   bool
	}
	procs := map[int]procInfo{}
	info := func(pid int) procInfo {
		if p, ok := procs[pid]; ok {
			return p
		}
		var p procInfo
		comm, err1 := readComm(e, pid)
		exe, err2 := readExe(e, pid)
		if err1 == nil && err2 == nil {
			p = procInfo{comm: comm, exe: exe, ok: true}
			if idx != nil {
				p.pkg, _ = idx.Lookup(strings.TrimSuffix(exe, " (deleted)"))
			}
			if cg, err := os.ReadFile(procPath(e, pid, "cgroup")); err == nil {
				p.unit = unitFromCgroup(string(cg))
			}
		}
		procs[pid] = p
		return p
	}

	seen := map[Listener]bool{}
	listeners := []Listener{}
	for _, ns := range nsOrder {
		if ctx.Err() != nil {
			return timeoutResult(categoryListeners, ctx)
		}
		tables, err := readNetTables(e, nsPIDs[ns])
		if err != nil {
			return errResult(categoryListeners, err.Error())
		}
		if tables == nil {
			if ns == hostNs {
				return errResult(categoryListeners, "socket tables of the host namespace not readable")
			}
			continue // every process of this namespace exited meanwhile
		}
		for _, proto := range procNetFiles {
			data, ok := tables[proto]
			if !ok {
				continue // no such table (e.g. IPv6 disabled): no such sockets
			}
			socks, err := parseProcNet(proto, data)
			if err != nil {
				return errResult(categoryListeners, fmt.Sprintf("%s: %v", proto, err))
			}
			for _, s := range socks {
				l := Listener{Protocol: s.protocol, Address: s.addr, Port: s.port, HostNetns: ns == hostNs}
				if opid, ok := owner[s.inode]; ok && s.inode != 0 {
					if p := info(opid); p.ok {
						l.Process, l.Exe, l.Package, l.Unit = p.comm, p.exe, p.pkg, p.unit
					}
				}
				if !seen[l] {
					seen[l] = true
					listeners = append(listeners, l)
				}
			}
		}
	}

	sortListeners(listeners)
	var truncated []string
	if len(listeners) > maxListeners {
		listeners = listeners[:maxListeners]
		truncated = append(truncated, categoryListeners)
	}
	return collectorResult{
		apply:     func(r *Runtime) { r.Listeners = &listeners },
		errs:      errs,
		truncated: truncated,
	}
}

// readNetTables reads the socket tables of a network namespace through the
// first of its processes that is still running. A missing table is left out
// of the result; nil means all processes exited.
func readNetTables(e *env, pids []int) (map[string]string, error) {
next:
	for _, pid := range pids {
		tables := map[string]string{}
		for _, proto := range procNetFiles {
			data, err := os.ReadFile(procPath(e, pid, "net/"+proto))
			if err == nil {
				tables[proto] = string(data)
				continue
			}
			if !processGone(err) {
				return nil, fmt.Errorf("%s: %v", proto, err)
			}
			if _, statErr := os.Stat(procPath(e, pid, "ns")); statErr != nil {
				continue next // the process exited; try the next one
			}
		}
		return tables, nil
	}
	return nil, nil
}

// scanSocketFDs records the socket inodes held by pid in owner, keeping the
// lowest PID per inode (pids are scanned in ascending order).
func scanSocketFDs(e *env, pid int, owner map[uint64]int) error {
	dir := procPath(e, pid, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if processGone(err) {
			return nil
		}
		return err
	}
	for _, ent := range entries {
		if ent.Type()&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(dir + "/" + ent.Name())
		if err != nil {
			if processGone(err) {
				continue
			}
			return err
		}
		rest, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
		if err != nil {
			continue
		}
		if _, ok := owner[inode]; !ok {
			owner[inode] = pid
		}
	}
	return nil
}

func sortListeners(ls []Listener) {
	sort.Slice(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		switch {
		case a.Protocol != b.Protocol:
			return a.Protocol < b.Protocol
		case a.Address != b.Address:
			return a.Address < b.Address
		case a.Port != b.Port:
			return a.Port < b.Port
		case a.Process != b.Process:
			return a.Process < b.Process
		case a.Exe != b.Exe:
			return a.Exe < b.Exe
		case a.Unit != b.Unit:
			return a.Unit < b.Unit
		case a.Package != b.Package:
			return a.Package < b.Package
		}
		return a.HostNetns && !b.HostNetns
	})
}

// parseProcNet parses a /proc/net/{tcp,tcp6,udp,udp6} table and returns
// listening TCP sockets or bound, unconnected UDP sockets.
func parseProcNet(proto, content string) ([]socket, error) {
	isTCP := strings.HasPrefix(proto, "tcp")
	var out []socket
	for i, line := range strings.Split(content, "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		local, remote, state := f[1], f[2], f[3]
		if isTCP && state != tcpListen {
			continue
		}
		if !isTCP && (state != udpClose || strings.Trim(remote, "0:") != "") {
			continue
		}
		addr, port, err := decodeAddrPort(local)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: inode: %w", i+1, err)
		}
		out = append(out, socket{protocol: proto, addr: addr.String(), port: port, inode: inode})
	}
	return out, nil
}

// decodeAddrPort decodes "0100007F:0035" style kernel addresses. The address
// is stored as 32-bit words in host (little-endian) byte order, the port as a
// big-endian hex number.
func decodeAddrPort(s string) (netip.Addr, int, error) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("malformed address %q", s)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("malformed port %q", hexPort)
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("malformed address %q", hexAddr)
	}
	b := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(b[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr, int(port), nil
}
