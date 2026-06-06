package certs

import "time"

// SetNowTime replaces the nowTime function used by DeriveStatus. Pass nil to
// restore the wall-clock default. Only for use in tests.
func SetNowTime(f func() time.Time) {
	if f == nil {
		nowTime = time.Now
	} else {
		nowTime = f
	}
}
