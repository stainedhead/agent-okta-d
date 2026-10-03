//go:build linux || darwin

package ipc_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/ipc"
)

func TestPeerCredReadsRealUnixPeer(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "ipc")
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	srvConn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvConn.Close() }()

	info, err := ipc.NewPeerCred().Read(srvConn)
	if err != nil {
		t.Fatal(err)
	}
	if info.UID != os.Getuid() || info.PID != os.Getpid() {
		t.Errorf("got uid=%d pid=%d, want %d %d", info.UID, info.PID, os.Getuid(), os.Getpid())
	}
	if info.GID != os.Getgid() && !contains(info.Groups, os.Getgid()) {
		t.Errorf("gid %d groups %v, want %d", info.GID, info.Groups, os.Getgid())
	}
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestPeerCredRejectsNonUnixConn(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if _, err := ipc.NewPeerCred().Read(a); err == nil {
		t.Error("want error for non-unix conn")
	}
}

func TestPeerCredClosedConnIsError(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "ipc")
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, "s")
	ln, _ := net.Listen("unix", p)
	defer func() { _ = ln.Close() }()
	c, _ := net.Dial("unix", p)
	srvConn, _ := ln.Accept()
	_ = c.Close()
	_ = srvConn.Close()
	if _, err := ipc.NewPeerCred().Read(srvConn); err == nil {
		t.Error("want error on closed conn")
	}
}
