//go:build linux

package ipc

import (
	"os"
	"strconv"
)

// exeOf is best effort: it is empty when /proc is unreadable.
func exeOf(pid int) string {
	p, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return p
}
