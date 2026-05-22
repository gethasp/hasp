//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package audit

func lockAuditFile(string) (func(), error) {
	return func() {}, nil
}
