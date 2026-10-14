# CyberPartha BOT v3 — User Guide

## Core Principles
1. **Policy First**: All programs require explicit operator policy review.
2. **Fail-Closed Scope**: Out-of-scope targets are strictly blocked by `ScopeGuard`.
3. **Single-Use Approval**: Every active test requires an individual, ephemeral `ApprovalToken`.
4. **Evidence-Based Findings**: Distinguishes `OBSERVED`, `HYPOTHESIS`, `INCONCLUSIVE`, and `VALIDATED`.

## Common Commands
```bash
# 1. Initialize a new research program
python3 bot.py init --name mytarget --domain example.com

# 2. Review and configure policy
python3 bot.py policy --program mytarget

# 3. Run permitted passive reconnaissance (Wayback, CT, AlienVault)
python3 bot.py recon --program mytarget

# 4. Generate endpoint intelligence & hypotheses
python3 bot.py suggestions --program mytarget

# 5. Review and approve a single active test
python3 bot.py next --program mytarget
python3 bot.py approve --program mytarget

# 6. Generate reproducible report draft
python3 bot.py report --program mytarget
```
