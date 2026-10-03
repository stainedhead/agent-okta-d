# Research

Feature: agent-okta-d-auto-review | Created: 2026-10-03 | Source PRD: specs/261003-agent-okta-d-auto-review/agent-okta-d-auto-review-PRD.md

## Research Questions
1. Which Okta error codes for a client_credentials private_key_jwt grant identify the client versus a policy denial? (FR-R02)
2. Can Linux supplementary groups be resolved safely through /proc/<pid>/status for the verified peer pid, and is it race-free? (FR-R05)
3. How to verify daemon identity before signalling a pid (peer pid over socket vs executable/start time) on both darwin and linux? (FR-R03)
4. Does Go's http.Client CheckRedirect suffice to block cross-host 307/308 re-send of POST bodies, and what is the minimal per-provider test? (FR-R08)
5. What is the right bounded-scrubber eviction policy without losing active secrets? (FR-R06)

## Industry Standards
[TBD]
## Existing Implementations
[TBD] (golang.org/x/net/netutil LimitListener concept; reimplement with stdlib only)
## API Documentation
[TBD]
## Best Practices
[TBD]
## Open Questions
See PRD section 7.
## References
Source PRD in this directory.
