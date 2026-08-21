//go:build !linux && !darwin

package config

import (
	"os"
	"time"
)

// statSnapshot is the fingerprint of the watched file compared by the
// stat-poll fallback. Platforms without a portable inode in syscall.Stat_t
// fall back to size and mtime.
type statSnapshot struct {
	size int64
	mod  time.Time
}

// statSnapshotOf stats path, reporting ok=false when the file is absent or
// unreadable. That transition is itself a change the poll must surface.
func statSnapshotOf(path string) (statSnapshot, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return statSnapshot{}, false
	}
	return statSnapshot{size: st.Size(), mod: st.ModTime()}, true
}
