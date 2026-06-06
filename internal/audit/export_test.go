package audit

// ExportNow replaces the package-level now function for tests and returns the
// previous value so the caller can restore it (typically via defer).
func ExportNow(f func() int64) func() int64 {
	prev := now
	now = f
	return prev
}
