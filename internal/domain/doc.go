// Package domain holds the frozen shared contracts of agent-okta-d: credential
// and wire types, the redacting SecretString, cache states, the error
// taxonomy, audit events and the interfaces (Signer, Provider, Deps, Clock,
// SecretStore, Sink, AuditSink, PeerCredReader, OktaTokenSource) that every
// adapter implements.
//
// The package performs no I/O and imports only the standard library. Concrete
// adapters (HTTP, KMS, Keychain, filesystem) live elsewhere and depend on this
// package, never the reverse.
//
// Changes to exported identifiers after workstream WS-0 need an ADR and a
// single owner (see specs/261003-agent-okta-d/plan.md). Reusable fakes for all
// interfaces live in the domaintest subpackage.
//
// Code that relies on an unconfirmed vendor behavior carries a comment of the
// form ASSUMPTION(A-01); every marker must be listed in docs/assumptions.md.
package domain
