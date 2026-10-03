// Package clienttest provides an in-process fake agent-okta-d daemon that
// listens on a unix socket, for testing code that uses pkg/client without a
// real daemon, credentials or network. It depends on the standard library
// only and keeps its own copy of the wire shapes, pinned by golden tests.
package clienttest
