package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type errListener struct{ net.Listener }

func (errListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }

func TestLimitListener(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "lim")
	defer func() { _ = os.RemoveAll(dir) }()
	inner, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 1)
	dial := func() net.Conn {
		c, err := net.Dial("unix", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1 := dial()
	defer func() { _ = c1.Close() }()
	s1, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// second Accept blocks while the slot is held, then is released by Close
	got := make(chan error, 1)
	c2 := dial()
	defer func() { _ = c2.Close() }()
	go func() { c, err := ln.Accept(); got <- err; _ = c.Close() }()
	select {
	case <-got:
		t.Fatal("Accept should block at the cap")
	case <-time.After(100 * time.Millisecond):
	}
	_ = s1.Close()
	_ = s1.Close() // double close must release only once
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	// Close unblocks a waiter with ErrClosed
	c3 := dial()
	defer func() { _ = c3.Close() }()
	s3, _ := ln.Accept() // takes the freed slot
	defer func() { _ = s3.Close() }()
	waiter := make(chan error, 1)
	go func() { _, err := ln.Accept(); waiter <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = ln.Close()
	if err := <-waiter; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v", err)
	}
	// accept error returns the slot
	el := newLimitListener(errListener{inner}, 1)
	for range 3 {
		if _, err := el.Accept(); err == nil {
			t.Fatal("want error")
		}
	}
}

// The limiter must not hide the raw conn from the real peer-credential reader.
func TestLimitedConnKeepsPeerCredentials(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "lim")
	defer func() { _ = os.RemoveAll(dir) }()
	inner, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 1)
	defer func() { _ = ln.Close() }()
	c, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sc.Close() }()
	info, err := NewPeerCred().Read(sc)
	if err != nil || info.UID != os.Getuid() {
		t.Fatalf("peer credentials through limiter: %+v %v", info, err)
	}
}
