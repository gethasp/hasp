//go:build !darwin && !linux

package audit

import "os"

func auditFileStateFromInfo(info os.FileInfo) fileState {
	return fileState{
		size:        info.Size(),
		modUnixNano: info.ModTime().UnixNano(),
	}
}
