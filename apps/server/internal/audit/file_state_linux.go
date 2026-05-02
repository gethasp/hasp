//go:build linux

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
		state.ctimeSec = stat.Ctim.Sec
		state.ctimeNsec = stat.Ctim.Nsec
		state.dev = stat.Dev
		state.ino = stat.Ino
		state.cacheable = true
	}
	return state
}
