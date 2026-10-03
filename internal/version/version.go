// Package version holds build stamps set with -ldflags -X (REL-4).
package version

import "fmt"

// Stamped at build time by the Makefile and release pipeline.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String renders "semver (commit, date)".
func String() string { return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date) }
