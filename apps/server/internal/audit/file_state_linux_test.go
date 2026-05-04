//go:build linux

package audit

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type linuxFileInfo struct {
	size int64
	mod  time.Time
	stat *syscall.Stat_t
}

func (i linuxFileInfo) Name() string       { return "audit.jsonl" }
func (i linuxFileInfo) Size() int64        { return i.size }
func (i linuxFileInfo) Mode() os.FileMode  { return 0o600 }
func (i linuxFileInfo) ModTime() time.Time { return i.mod }
func (i linuxFileInfo) IsDir() bool        { return false }
func (i linuxFileInfo) Sys() any           { return i.stat }

func TestLinuxAuditFileStateFromInfoCopiesStatMetadata(t *testing.T) {
	mod := time.Unix(123, 456).UTC()
	info := linuxFileInfo{
		size: 42,
		mod:  mod,
		stat: &syscall.Stat_t{
			Ctim: syscall.Timespec{Sec: 987, Nsec: 654},
			Dev:  321,
			Ino:  789,
		},
	}

	state := auditFileStateFromInfo(info)

	if !state.cacheable {
		t.Fatal("linux stat metadata must make audit file state cacheable")
	}
	if state.size != info.size || state.modUnixNano != mod.UnixNano() {
		t.Fatalf("file state size/mod = (%d, %d), want (%d, %d)", state.size, state.modUnixNano, info.size, mod.UnixNano())
	}
	if state.ctimeSec != info.stat.Ctim.Sec || state.ctimeNsec != info.stat.Ctim.Nsec {
		t.Fatalf("ctime = (%d, %d), want (%d, %d)", state.ctimeSec, state.ctimeNsec, info.stat.Ctim.Sec, info.stat.Ctim.Nsec)
	}
	if state.dev != info.stat.Dev || state.ino != info.stat.Ino {
		t.Fatalf("identity = (%d, %d), want (%d, %d)", state.dev, state.ino, info.stat.Dev, info.stat.Ino)
	}
}
