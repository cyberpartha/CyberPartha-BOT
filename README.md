# CyberPartha BOT v3 — Phase 5

CyberPartha BOT v3 is a policy-gated security research assistant for authorized research and local-lab validation.

It is not an autonomous vulnerability scanner or bug bounty finding confirmation service.

## Capabilities

### Phase 1 — Safety Foundation
- Scope and policy controls
- Approval and request-budget mechanisms
- Emergency STOP and audit components

### Phase 2 — Passive Reconnaissance
- Policy-gated collection from supported public archives
- Scope filtering and checkpointing

### Phase 3 — Offline Endpoint Intelligence
- Analysis of sanitized endpoint metadata
- Explainable, heuristic research hypotheses
- No vulnerability confirmation

### Phase 4 — Local-Lab Validation
- Explicit local-lab ownership confirmation
- Loopback-only HTTP GET validation adapter
- Single-use approval tokens with expiry
- Redirects disabled and request limits enforced
- Observations are not confirmed vulnerabilities

### Phase 5 — Offline Reporting
- JSON and Markdown research summaries
- Conservative severity classification
- Researcher assertions explicitly identified as unverified
- Credential-pattern checks and limited sensitive-data redaction
- No automatic independent vulnerability confirmation

## Quick Start

Run:

    python3 bot.py --help

For offline research summaries:

    python3 bot.py phase5-report --program YourProgram

For automated tests:

    python3 -m unittest discover -s tests -q

## Authorization

Only research assets explicitly permitted by the applicable program policy.

Local-lab execution requires ownership or control of the local service and explicit authorization.

Do not enable permission flags merely to bypass safety restrictions.

## Important Limitations

- No guaranteed vulnerability discovery or bounty reward
- No automatic verification of program authorization
- No complete secret or personal-data detection
- No general-purpose live-target active scanning
- Reports require human review before submission

See SECURITY-LIMITATIONS.md and INSTALLATION.md.
