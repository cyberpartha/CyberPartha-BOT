# CyberPartha BOT v3 — Changelog

## [3.0.0] - 2026-10-14
### Added
- **Phase 1: Safety Foundation**
  - Fail-closed `ScopeGuard` with subdomain spoofing and private IP protection.
  - Ephemeral, single-use `ApprovalToken` and `ApprovalStore`.
  - Leaky-bucket `RateLimiter` and unified `SafetyGuard`.
  - Append-only JSONL `AuditLogger` with automatic credential scrubbing.
  - SQLite `StateDB` in WAL mode with meta, hosts, suggestions, and audit logs.
- **Phase 2: Policy Intelligence & Smart Passive Recon**
  - Section-aware policy parser for HackerOne, Bugcrowd, Intigriti, and Custom platforms.
  - Checkpoint-based, resumable passive connectors for Certificate Transparency, Wayback Machine, and AlienVault OTX.
  - Policy change invalidation via SHA-256 fingerprinting.
- **Phase 3: Endpoint Intelligence & AI Reasoning**
  - Endpoint path normalizer with dynamic ID/UUID parameter clustering and query sanitization.
  - Vulnerability reasoning engine across OWASP categories with explainable hypotheses.
  - Pluggable AI provider interface with prompt injection defenses and offline fallback.
- **Phase 4: Approval-Gated Validation**
  - Single-test approval runner with explicit parameter display modal.
  - Dual-account owned-object authorization adapter (IDOR/BOLA).
  - Security headers and configuration adapter.
- **Phase 5: Reporting, Performance & Final Release**
  - Markdown and JSON bug bounty report generator.
  - Memory and latency benchmark test suite (< 150MB RSS, < 2.0s per 1k ops).
  - Automated `install.sh` installation script with timestamped backups.
