# Assumptions register

Every item the PRD marks unconfirmed stays an explicit assumption. Code that depends on one carries a comment `ASSUMPTION(A-01)` (the tolerant form `ASSUMPTION(A01)` is also recognized), and the test `internal/domain/assumptions_test.go` fails if a marker names an id that is not listed here (AC-016). Each row is settled later by the matching row in `m0-spike-checklist.md`; until then the working assumption is implemented behind an interface and must not be treated as fact. Source: `specs/261003-agent-okta-d/research.md`, PRD sections 9.2 and 16.

| ID | Assumption | Working behavior in code | Settled by (M0 checklist row) |
|---|---|---|---|
| A-01 | Okta accepts ES256 client assertions (PRD 6.3, Q6) | RS256 default; ES256 supported but flagged | A-01 |
| A-02 | Minimum Okta access-token lifetime for `agents-snow` is 10 min | TTL read from the response, never hardcoded | A-02 |
| A-03 | `sub` of a client-credentials access token equals the client id (PRD 7.1) | Daemon never validates `sub`; documentation only | A-03 |
| A-04 | Okta has a usable revocation call for client-credential tokens (PRD 13) | Revoke hook is best effort; errors ignored | A-04 |
| A-05 | GitHub PAT expiry header `github-authentication-token-expiration` and noreply email form (GH-6, GH-8) | Expiry recorded at enroll; header optional | A-05 |
| A-06 | The GitHub CLI public OAuth app is allowed for EMU users (GH-5, Q3) | `oauth_client_id` configurable; default flagged | A-06 |
| A-07 | Graph refresh flow, Conditional Access and CAE invalidation behavior (MG-1, MG-5, Q11) | Every `invalid_grant` variant maps to `reauth_required` | A-07 |
| A-08 | SCIM deprovision delay and Entra kill-switch propagation (PRD 13) | Not testable offline; measured in the drill | A-08 |
| A-09 | Hermes re-reads MCP headers/config without restart; env/PATH shim support (Q2) | File sink re-rendered; proxy deferred (P2) | A-09 |
| A-10 | KMS returns DER ECDSA that converts to JOSE raw R and S (FR-2) | Conversion implemented and unit tested with known vectors | A-10 |
| A-11 | WSL2 can run the service definition (systemd) (PRD 17.7) | Documented as unconfirmed | A-11 |
| A-12 | Apple Developer ID/notarization available; Keychain needs cgo (REL-1a) | Keychain code behind build tag; darwin build on a mac runner | A-12 |
| A-20 | Okta reports a per-provider authorization-server policy or scope denial of a client_credentials grant as `access_denied` or `invalid_grant` (FR-R02); unconfirmed against a real tenant | Only `invalid_client` and `unauthorized_client` are definitive (two within 30 s revoke everything); `access_denied` and `invalid_grant` are provider errors that back off and degrade that one provider | A-20 |
