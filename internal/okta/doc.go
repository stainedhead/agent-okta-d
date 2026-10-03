// Package okta builds Okta private_key_jwt client assertions and implements
// domain.OktaTokenSource on top of them (PRD 6.3, 6.4, FR-2, FR-6, FR-9).
//
// It performs no caching, retries or state tracking: callers (the cache
// use case) classify results with the domain error taxonomy.
package okta
