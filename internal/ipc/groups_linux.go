//go:build linux

package ipc

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// procRoot is /proc; tests point it at a fixture.
var procRoot = "/proc"

// groupsOf returns the supplementary groups of pid from /proc/<pid>/status.
// SO_PEERCRED yields only the primary gid, so this closes the gap with darwin
// (FR-R05). The pid comes from the kernel for a connected socket. It fails
// closed: on any read or parse problem it returns nil, so only the primary
// gid can match the allow-list.
func groupsOf(pid int) []int {
	f, err := os.Open(procRoot + "/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "Groups:")
		if !ok {
			continue
		}
		var out []int
		for _, field := range strings.Fields(rest) {
			g, err := strconv.Atoi(field)
			if err != nil || g < 0 {
				return nil
			}
			out = append(out, g)
		}
		return out
	}
	return nil
}
