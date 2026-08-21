//go:build linux || darwin

package config

import (
	"os"
	"syscall"
	"time"
)

// statSnapshot is the fingerprint of the watched file compared by the
// stat-poll fallback. The inode is included so atomic replacements that
// preserve size and mtime (rename-over-target from a preserved-stat copy)
// are still detected.
type statSnapshot struct {
	size int64
	mod  time.Time
	ino  uint64
}

// statSnapshotOf stats path, reporting ok=false when the file is absent or
// unreadable. That transition is itself a change the poll must surface.
func statSnapshotOf(path string) (statSnapshot, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return statSnapshot{}, false
	}
	snap := statSnapshot{size: st.Size(), mod: st.ModTime()}
	if raw, ok := st.Sys().(*syscall.Stat_t); ok {
		snap.ino = raw.Ino
	}
	return snap, true
}
