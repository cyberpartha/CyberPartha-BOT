"""
Passive Recon Collector orchestrator.
Manages sources, strict scope filtering, SQLite checkpoints, bounded concurrency,
pause/resume, and policy change invalidation.
"""
from __future__ import annotations
import hashlib, json
from typing import Dict, List, Any, Optional
from core.scope.guard import ScopeGuard
from core.storage.db import StateDB
from .sources.ct import CertificateTransparencySource
from .sources.wayback import WaybackSource
from .sources.alienvault import AlienVaultSource

SOURCES_MAP = {
    "ct": CertificateTransparencySource,
    "wayback": WaybackSource,
    "alienvault": AlienVaultSource
}

class ReconCollector:
    def __init__(self, program_name: str, profile_data: Dict[str, Any], db: StateDB):
        self.program_name = program_name
        self.profile = profile_data
        self.db = db
        self.scope_guard = ScopeGuard(
            allowed_domains=self.profile.get("allowed_domains", []),
            excluded_domains=self.profile.get("excluded_domains", [])
        )

    def compute_fingerprint(self) -> str:
        data = {
            "allowed": sorted(self.profile.get("allowed_domains", [])),
            "excluded": sorted(self.profile.get("excluded_domains", [])),
            "policy_url": self.profile.get("policy_url", ""),
            "policy_reviewed": self.profile.get("policy_reviewed", False),
            "passive_allowed": self.profile.get("passive_allowed", False),
            "ai_allowed": self.profile.get("ai_allowed", False)
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def run(self, sources: Optional[List[str]] = None) -> Dict[str, Any]:
        # 1. Enforce strict permissions
        if not self.profile.get("policy_reviewed") or not self.profile.get("passive_allowed"):
            raise PermissionError("Passive reconnaissance not authorized by policy or human review.")

        if self.db.is_paused():
            return {"status": "paused", "message": "Execution is paused; zero network traffic sent."}

        # 2. Check fingerprint for policy invalidation
        current_fp = self.compute_fingerprint()
        stored_fp = self.db.get_meta("phase2_fingerprint")
        if stored_fp is None:
            # Existing checkpoints predate fingerprint tracking; retain them on
            # first migration instead of unexpectedly repeating network calls.
            self.db.set_meta("phase2_fingerprint", current_fp)
        elif stored_fp != current_fp:
            # Verified change of policy or scope invalidates old checkpoints.
            self.db.clear_meta_prefix("phase2_done:")
            self.db.set_meta("phase2_fingerprint", current_fp)

        selected = sources or ["ct", "wayback"]
        timeout = min(max(int(self.profile.get("passive_timeout_seconds", 10)), 2), 20)
        limit = min(max(int(self.profile.get("max_ct_results", 100)), 10), 200)

        tasks_run = 0
        discovered_count = 0

        for domain in self.profile.get("allowed_domains", []):
            for src_name in selected:
                if src_name not in SOURCES_MAP:
                    continue
                checkpoint_key = f"phase2_done:{src_name}:{domain}"
                if self.db.get_meta(checkpoint_key) == "1":
                    continue  # Checkpoint resume: already completed

                if self.db.is_paused():
                    return {"status": "paused", "message": "Paused during execution.", "tasks_run": tasks_run}

                src_cls = SOURCES_MAP[src_name]
                src_instance = src_cls(timeout=timeout, max_results=limit)
                hosts = src_instance.fetch_subdomains(domain)

                for h in hosts:
                    if self.scope_guard.is_allowed_host(h):
                        if self.db.add_host(h, src_name):
                            discovered_count += 1

                self.db.set_meta(checkpoint_key, "1")
                tasks_run += 1

        all_hosts = self.db.get_all_hosts()
        return {
            "status": "completed",
            "tasks_run": tasks_run,
            "new_hosts": discovered_count,
            "total_in_scope_hosts": len(all_hosts),
            "hosts": all_hosts
        }
