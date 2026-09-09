//go:build !unix

package hooks

import "os"

func hookExecutable(_ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0
}
