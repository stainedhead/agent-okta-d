// Package cache is the credential cache use case (PRD FR-3..FR-6, FR-17,
// section 13): one entry per (provider, audience, scope) with the state machine
// of domain.State, single-flight minting, a proactive refresh scheduler,
// exponential backoff, degraded, revoked and reauth_required handling.
//
// It depends only on internal/domain; time comes from domain.Clock so the whole
// behaviour runs on a fake clock (see the 24 h simulation test).
//
// Local decisions not covered by the PRD (none is an unconfirmed vendor
// claim, so none has an ASSUMPTION id):
//   - A margin larger than half the credential TTL is capped to half the TTL.
//   - A failed first mint (no credential to serve) goes straight to degraded.
//   - Non-transient, non-auth failures (ErrConfig, ErrPolicy, ErrProvider,
//     unknown) are retried with the same backoff and never lead to revoked.
//   - Entering degraded removes the entry's sinks; a later successful mint
//     rewrites them.
//   - The first definitive error keeps serving while it is confirmed with a
//     retry after the minimum backoff; the confirmation window is per entry,
//     the resulting revoked state is daemon wide.
//   - Per-entry Options may override fraction, jitter and margin (for example
//     AWS-2 needs refresh at <= 50 %, so its entry uses fraction 0.45).
package cache
