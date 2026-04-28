package app

import (
	"errors"
	"strings"
	"time"
)

// errGrantWindowMissing is returned when a caller picks scope=window for any
// of project/secret/convenience grants but does not pass --grant-window
// <duration>. Letting a silent 15m default through means the user gets
// 15 minutes of future secret access they did not opt into; making the
// duration explicit closes that gap.
var errGrantWindowMissing = errors.New("--grant-window duration is required when --grant-project, --grant-secret, or --grant-convenience is 'window'")

const grantWindowHardCeiling = 7 * 24 * time.Hour

func validateGrantWindow(projectGrant, secretGrant, convenienceGrant string, window time.Duration) error {
	if window < 0 {
		return errors.New("--grant-window must not be negative")
	}
	if window > grantWindowHardCeiling {
		return errors.New("--grant-window must not exceed 7d")
	}
	if window == 0 && anyScopeIsWindow(projectGrant, secretGrant, convenienceGrant) {
		return errGrantWindowMissing
	}
	return nil
}

func anyScopeIsWindow(scopes ...string) bool {
	for _, s := range scopes {
		if strings.TrimSpace(s) == "window" {
			return true
		}
	}
	return false
}
