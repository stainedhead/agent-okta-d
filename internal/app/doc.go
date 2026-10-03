// Package app wires the daemon: config -> signer -> Okta token source -> cache
// -> providers -> sink -> ipc -> obs, and implements the operator commands
// (run, token, status, doctor, revoke, env, configure, enroll, credential
// helper). cmd/agent-okta-d only calls Main. Every external seam (clock, KMS,
// Secrets Manager, STS, signals, process identity) is injected through Env so
// the package runs end to end against fakes.
//
// INT decisions (also in specs/261003-agent-okta-d/implementation-notes.md):
//   - The AWS SDK adapters (KMS, Secrets Manager, STS) are not part of this
//     build; DefaultEnv leaves them nil and the wiring answers ErrConfig
//     ("not available in this build") when a config needs one.
//   - There is no revoke endpoint (the wire API is frozen). `revoke` signals
//     the daemon (SIGUSR1) through a pidfile next to the socket and wipes
//     the sinks locally, so it also works when the daemon is down.
//   - Startup self-test refuses a provider with a config, policy or provider
//     error (not registered, so the API answers 404). Transient errors and
//     reauth_required keep the provider; a definitive Okta rejection is fatal
//     and exits 77. Probes run in doctor only.
package app
