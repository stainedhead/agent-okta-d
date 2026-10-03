package client

import "testing"

func TestDefaultSocketForPlatform_ProposedA13(t *testing.T) {
	if got := defaultSocketFor("darwin"); got != "/var/run/agentd/agentd.sock" {
		t.Fatal(got)
	}
	if got := defaultSocketFor("linux"); got != "/run/agentd/agentd.sock" {
		t.Fatal(got)
	}
}
