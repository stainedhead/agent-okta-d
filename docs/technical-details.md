# Technical details

Technical design belongs here: component architecture, the Signer and Provider interfaces, cache state machine, error taxonomy, configuration reference, and revocation and exposure windows. Until this is written out, the source of truth is `../agent-okta-d-PRD.md` (sections 5, 8, 9, 10 and 13).


## Shared contracts (frozen by WS-0)
`internal/domain` is the single source for: `Credential`, `SecretString`, `Key`, `CacheEntry`, `State` and `CanTransition`, the error taxonomy (`ErrTransient`, `ErrAuthDefinitive`, `ErrConfig`, `ErrPolicy`, `ErrProvider`, plus `ErrReauthRequired`, `ErrRevoked`, `ErrNotFound`, `ErrVersionConflict`), exit codes (0, 77, 78), `AuditEvent`, `Scrubber`, the daemon-side wire types (`Wire*`, error codes, `HTTPStatus`) and the interfaces `Clock`, `Signer`, `Provider`, `Deps`, `OktaTokenSource`, `SecretStore`, `Sink`, `PeerCredReader`, `AuditSink`. Fakes for all of them: `internal/domain/domaintest`. Wire JSON goldens: `internal/domain/testdata/wire`. Conventions every workstream follows: a provider returns `ErrReauthRequired` for an expired user credential and never retries it; only Okta definitive errors are `ErrAuthDefinitive`; secrets cross package boundaries as `SecretString`; `Credential.Validate()` must pass before anything is cached or served.
