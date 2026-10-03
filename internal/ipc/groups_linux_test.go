//go:build linux

package ipc

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGroupsOfParsesProcStatus(t *testing.T) {
	root := t.TempDir()
	write := func(pid, body string) {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "status"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "Name:\tx\nGroups:\t100 2000 30000 \nVmRSS:\t1 kB\n")
	write("11", "Name:\tx\nGroups:\t\nVmRSS:\t1 kB\n")
	write("12", "Name:\tx\nGroups:\t100 bogus 200\n")
	write("13", "Name:\tx\n")
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	if got := groupsOf(10); !slices.Equal(got, []int{100, 2000, 30000}) {
		t.Errorf("got %v", got)
	}
	// fail closed: empty, malformed, missing line, missing process -> no extra groups
	for _, pid := range []int{11, 12, 13, 99} {
		if got := groupsOf(pid); got != nil {
			t.Errorf("pid %d: want nil, got %v", pid, got)
		}
	}
}

func TestGroupsOfRealProcess(t *testing.T) {
	want, err := os.Getgroups()
	if err != nil || len(want) == 0 {
		t.Skip("no supplementary groups")
	}
	got := groupsOf(os.Getpid())
	for _, g := range want {
		if !slices.Contains(got, g) {
			t.Errorf("group %d missing from %v", g, got)
		}
	}
}
