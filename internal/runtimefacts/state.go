package runtimefacts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// moduleIndexMaxAge is how long a sent module index stays valid. After that
// the full index is sent again even if the hash did not change.
const moduleIndexMaxAge = 24 * time.Hour

// ApplyModuleIndexState reduces the module index to its hash when the state
// file says the same index was accepted by the server within the last 24
// hours. A missing, unreadable, stale or different state file keeps the full
// index.
func ApplyModuleIndexState(r *Runtime, stateFile string, now time.Time) {
	if r.Kernel == nil || r.Kernel.ModuleIndex == nil || r.Kernel.ModuleIndex.Available == nil {
		return
	}
	info, err := os.Stat(stateFile)
	if err != nil || now.Sub(info.ModTime()) > moduleIndexMaxAge {
		return
	}
	data, err := os.ReadFile(stateFile)
	if err != nil || strings.TrimSpace(string(data)) != r.Kernel.ModuleIndex.Hash {
		return
	}
	r.Kernel.ModuleIndex.Available = nil
	r.Kernel.ModuleIndex.Builtin = nil
}

// SaveModuleIndexState records the hash of a module index the server has
// accepted. Call it only after the report was accepted with HTTP 2xx, and
// only when the full index was part of it (Runtime.FullModuleIndexHash).
func SaveModuleIndexState(stateFile, hash string) error {
	if hash == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(stateFile), 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}
	tmp := stateFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(hash+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write module index state: %w", err)
	}
	if err := os.Rename(tmp, stateFile); err != nil {
		return fmt.Errorf("failed to rename module index state file: %w", err)
	}
	return nil
}
