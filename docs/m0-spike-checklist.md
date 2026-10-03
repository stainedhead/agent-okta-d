# M0 spike checklist

M0 (PRD section 14) needs real tenants and is not performed in the build phase. This checklist replaces it: one row per unconfirmed item in `assumptions.md`. Humans run it later against sandbox systems and write the spike report; each result either confirms the working assumption or changes the named code. Tick a row only with evidence (log excerpt, screenshot reference, ticket id), never with secrets or real tenant identifiers.

| ID | What to test | Expected result | Code assumption it settles | Status |
|---|---|---|---|---|
| A-01 | Register an ES256 public JWK on a test API Services app and request a token with an ES256 `private_key_jwt` | Okta issues a token | `internal/signer` ES256 path and `internal/okta` alg selection; if refused, drop ES256 from KMS/TPM defaults | [ ] |
| A-02 | Configure `agents-snow` with the shortest allowed access-token lifetime and read `expires_in` | Lifetime is at least 10 min, taken from the response | Scheduler never hardcodes TTL; `min_ttl_seconds` default | [ ] |
| A-03 | Decode an access token from a client-credentials grant | `sub` equals the client id | Documentation only (AWS trust policy condition) | [ ] |
| A-04 | Call the Okta revocation endpoint with a client-credential access token, then use the token | Token is rejected after revoke, or the call is unsupported | Provider `Revoke` hook for the Okta token (best effort) | [ ] |
| A-05 | Create a fine-grained PAT for an EMU test user and inspect the response headers; check the noreply email form | `github-authentication-token-expiration` header present; email form matches | `internal/provider/github` expiry recording, `configure git` identity | [ ] |
| A-06 | Run device flow with the GitHub CLI public client id for an EMU user | Allowed, or blocked by enterprise policy | `oauth_client_id` default for `oauth_device` mode | [ ] |
| A-07 | Run the Graph refresh grant, then trigger Conditional Access / CAE invalidation and password reset | Refresh keeps rotating; invalidation returns `invalid_grant` or a claims challenge | `internal/provider/msgraph` error mapping to `reauth_required` | [ ] |
| A-08 | Disable the agent in AD/Okta and time SCIM suspension in GitHub EMU and Entra sign-in revocation | Delay is measured and recorded | Runbook exposure windows (PRD 13) | [ ] |
| A-09 | Point Hermes at the file sink for MCP headers and rotate the secret without restart | Hermes picks up the new value, or needs a restart | Atlassian sink design (`internal/provider/secret`), proxy decision | [ ] |
| A-10 | Sign with a real KMS ECC key and verify the JOSE signature at Okta | R and S conversion verifies | `internal/signer/kms` DER to JOSE conversion | [ ] |
| A-11 | Install the systemd unit under WSL2 on amd64 and arm64 | Daemon starts and restarts per policy, or WSL needs another supervisor | Install documentation for WSL | [ ] |
| A-12 | Notarize a darwin/arm64 build with a Developer ID and build the Keychain signer with and without cgo | Signed build runs; cgo requirement known | Keychain signer build tags, CD macOS runner | [ ] |
| A-20 | On a sandbox tenant, deny one auth server with an access policy or remove a scope grant, then request a client_credentials token; separately disable the app | Policy denial returns `access_denied` or `invalid_grant` and affects only that provider; a disabled app returns `invalid_client` | `internal/okta` `definitive` set | [ ] |
