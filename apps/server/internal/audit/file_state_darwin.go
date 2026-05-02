//go:build darwin

package audit

import (
	"os"
	"syscall"
)

func auditFileStateFromInfo(info os.FileInfo) fileState {
	state := fileState{
		size:        info.Size(),
		modUnixNano: info.ModTime().UnixNano(),
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		state.ctimeSec = stat.Ctimespec.Sec
		state.ctimeNsec = stat.Ctimespec.Nsec
		state.dev = uint64(stat.Dev)
		state.ino = stat.Ino
		state.cacheable = true
	}
	return state
}
