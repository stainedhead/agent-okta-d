package client_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stainedhead/agent-okta-d/pkg/client"
	"github.com/stainedhead/agent-okta-d/pkg/client/clienttest"
)

// fakeDaemon starts the in-process fake the examples talk to. Real code uses
// client.New() with no options and reaches the real daemon.
func fakeDaemon() (*client.Client, func()) {
	srv := clienttest.New(exampleT{})
	t0 := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	srv.SetCredential("aws", clienttest.Credential{TokenType: "Bearer", AccessToken: "tok-123", IssuedAt: t0, ExpiresAt: t0.Add(time.Hour), Audience: "sts.amazonaws.com"})
	srv.SetProviderError("github", clienttest.Error{Code: clienttest.CodeDegraded, State: "degraded", RetryAfter: 30 * time.Second})
	return client.New(client.WithSocketPath(srv.SocketPath())), srv.Close
}

func Example() {
	c, stop := fakeDaemon()
	defer stop()

	cred, err := c.Credential(context.Background(), "aws")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// The token prints redacted; call Reveal only where it is used.
	fmt.Println(cred.TokenType, cred.AccessToken, cred.Audience, len(cred.AccessToken.Reveal()) > 0)
	// Output: Bearer [redacted] sts.amazonaws.com true
}

func ExampleClient_Credential_errors() {
	c, stop := fakeDaemon()
	defer stop()

	_, err := c.Credential(context.Background(), "github")
	switch {
	case errors.Is(err, client.ErrDegraded):
		d, _ := client.RetryAfter(err)
		fmt.Println("degraded, retry in", d)
	case errors.Is(err, client.ErrRevoked):
		fmt.Println("revoked")
	}
	_, err = c.Credential(context.Background(), "nope")
	fmt.Println(errors.Is(err, client.ErrNotConfigured))
	// Output:
	// degraded, retry in 30s
	// true
}

func ExampleNew() {
	c := client.New(client.WithSocketPath("/run/agentd/agentd.sock"), client.WithTimeout(2*time.Second))
	defer c.Close()
	fmt.Println(c.SocketPath())
	// Output: /run/agentd/agentd.sock
}

// exampleT adapts examples (which have no *testing.T) to clienttest.New.
type exampleT struct{}

func (exampleT) Helper()                   {}
func (exampleT) Fatalf(f string, a ...any) { panic(fmt.Sprintf(f, a...)) }
func (exampleT) Cleanup(func())            {}
