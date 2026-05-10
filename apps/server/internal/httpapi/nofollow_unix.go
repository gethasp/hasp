//go:build unix || darwin || linux

package httpapi

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW
