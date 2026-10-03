# Research: agent-okta-d
Date: 2026-10-03 | Source PRD: `agent-okta-d-PRD.md`

No live system is consulted in this build. Each question below is an **assumption** (A-xx) implemented behind an interface and settled later by a human spike (`docs/m0-spike-checklist.md`).

## Research Questions / Assumptions
| ID | Question | Working assumption in code |
|---|---|---|
| A-01 | Does Okta accept ES256 client assertions? (PRD 6.3, Q6) | RS256 default; ES256 supported but flagged |
| A-02 | Minimum Okta access-token lifetime for `agents-snow` (10 min?) | TTL read from the response, not hardcoded |
| A-03 | Is `sub` of a client-credentials access token equal to client_id? (7.1) | Yes; daemon never validates `sub`, doc only |
| A-04 | Does Okta have a usable token-revocation call for client-credential tokens? (13) | Revoke hook best effort, errors ignored |
| A-05 | GitHub: PAT expiry header `github-authentication-token-expiration` and noreply email form (GH-6, GH-8) | Expiry recorded at enroll; header optional |
| A-06 | Is the GitHub CLI public OAuth app allowed for EMU users? (GH-5, Q3) | `oauth_client_id` configurable, default flagged |
| A-07 | Graph refresh flow behavior, Conditional Access/CAE invalidation (MG-1, MG-5, Q11) | All `invalid_grant` variants map to `reauth_required` |
| A-08 | SCIM deprovision delay; Entra kill-switch propagation (13) | Not testable offline; spike item |
| A-09 | Does Hermes re-read MCP headers/config without restart; env/PATH shim support (Q2) | File sink re-rendered; proxy deferred (P2) |
| A-10 | KMS DER to JOSE raw R||S conversion (FR-2) | Implemented and unit tested with known vectors |
| A-11 | WSL2 service (systemd) support (17.7) | Documented as unconfirmed |
| A-12 | Apple Developer ID/notarization and cgo requirement for Keychain (REL-1a) | Keychain code behind build tag; darwin build on mac runner |

## Industry Standards
RFC 7523 (JWT client auth), RFC 8628 (device flow), RFC 6749 (client credentials), git credential protocol, AWS web-identity token file.
## Existing Implementations
`okta-aws-cli` m2m mode (reference only).
## API Documentation
Links in PRD Appendix A.
## Best Practices
Atomic file writes, single-flight, redacting types.
## Open Questions
PRD section 16 and 17.7 carried unchanged.
## References
PRD Appendix A.
