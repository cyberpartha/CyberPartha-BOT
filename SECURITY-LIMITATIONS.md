# CyberPartha BOT v3 — Security Limitations

## 1. Authorization and Scope

CyberPartha BOT is intended only for authorized security research.

Users must independently verify the applicable program policy,
asset scope, testing restrictions and AI usage permissions.

The tool cannot independently establish legal authorization.

## 2. Reconnaissance

Passive reconnaissance may contact supported third-party
information services when explicitly enabled.

Passive collection is not necessarily network-free.

Do not test unlisted or out-of-scope targets.

## 3. Local-Lab Validation

Phase 4 provides a restricted HTTP GET adapter for
researcher-owned or controlled loopback services.

Restrictions include:

- Explicit local-lab ownership confirmation.
- Existing authorized local-lab profile.
- Single-use approval token with expiry.
- Loopback-only HTTP targets.
- One HTTP request attempt per approved execution.
- Redirects disabled.
- Request timeout and response-size limits.
- Emergency STOP and pause controls.

Local-lab observations do not establish vulnerabilities
in external systems.

## 4. Reporting and Evidence

Phase 5 generates offline JSON and Markdown reports.

Researcher-provided VALIDATED conclusions are assertions,
not independently confirmed vulnerabilities.

Severity defaults to INFORMATIONAL and requires human review.

HTTP 200, missing headers and other observations do not,
by themselves, establish security impact.

## 5. Sensitive Data

Reporting implements limited protective controls:

- Credential-related headers are excluded.
- Raw request and response bodies are redacted.
- URL credentials, query strings and fragments are removed
  from affected-asset output.
- Certain account and observation fields are omitted.
- Recognizable credential patterns in selected free-text
  fields cause report generation to be rejected.

These controls are not comprehensive.

Sensitive values may still appear in URL paths, allowlisted
header values, free-text fields or unsupported credential
formats.

Review every report manually before sharing.

## 6. Installation and Dependencies

The installer may access the internet to install Python
dependencies.

Its existing backup covers selected runtime directories,
not the entire source tree.

The installer stores selected runtime-directory backups under the current users HOME directory.

## 7. Important Restrictions

- No general-purpose active vulnerability scanner.
- No autonomous vulnerability confirmation.
- No guarantee of zero false positives.
- No guarantee of complete secret or personal-data removal.
- No guarantee of bug bounty rewards.
- Never use the tool to bypass program restrictions.

## 8. Researcher Responsibility

Keep explicit authorization records, protect credentials,
respect rate limits and program policies, and independently
verify findings before submission.
