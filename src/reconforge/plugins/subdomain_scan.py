"""Subdomain enumeration plugin for ReconForge.

Responsibilities:
- Enumerate subdomains using multiple tools (subfinder, assetfinder, crt.sh)
- Merge and deduplicate results from all sources
- Provide comprehensive subdomain list

Design:
- Runs multiple tools concurrently
- Merges results and removes duplicates
- Depends on normalize_url for domain
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from typing import ClassVar

import requests

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class SubdomainScanPlugin(BasePlugin):
    """Enumerate subdomains using multiple tools."""

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        return "subdomain_scan"

    @property
    def description(self) -> str:
        return "Enumerate subdomains using subfinder, assetfinder, and crt.sh"

    def setup(self, **kwargs: object) -> None:
        missing = []
        if shutil.which("subfinder") is None:
            missing.append("subfinder")
        if shutil.which("assetfinder") is None:
            missing.append("assetfinder")
        if missing:
            raise RuntimeError(
                f"Missing tools: {', '.join(missing)}. "
                "Install with: apt install subfinder assetfinder"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        start = time.perf_counter()

        normalize_result = upstream_results.get("normalize_url")
        if not normalize_result or not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error="normalize_url result not available or failed",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        is_ip = normalize_result.metadata.get("is_ip", False)

        if is_ip:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": 0, "skipped": "ip_address"},
            )

        all_subdomains: set[str] = set()
        sources: dict[str, object] = {}

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self._run_subfinder, domain): "subfinder",
                executor.submit(self._run_assetfinder, domain): "assetfinder",
                executor.submit(self._run_crtsh, domain): "crtsh",
            }
            for future in as_completed(futures):
                source = futures[future]
                try:
                    subs = future.result()
                    sources[source] = len(subs)
                    all_subdomains.update(subs)
                except Exception as e:
                    sources[source] = f"error: {e}"

        filtered = {s for s in all_subdomains if s.endswith(f".{domain}") or s == domain}

        return create_success_result(
            module=self.name,
            data=sorted(filtered),
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"domain": domain, "count": len(filtered), "sources": sources},
        )

    def _run_subfinder(self, domain: str) -> set[str]:
        """Run subfinder and return subdomains."""
        try:
            proc = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-t", "10"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0:
                return set()

            subs: set[str] = set()
            for line in proc.stdout.splitlines():
                line = line.strip().lower()
                if line and "*" not in line:
                    subs.add(line)
            return subs
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return set()

    def _run_assetfinder(self, domain: str) -> set[str]:
        """Run assetfinder and return subdomains."""
        try:
            proc = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                return set()
            return {l.strip() for l in proc.stdout.splitlines() if l.strip()}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return set()

    def _run_crtsh(self, domain: str) -> set[str]:
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json", timeout=5,
            )
            if resp.status_code != 200:
                return set()
            subs: set[str] = set()
            for entry in resp.json():
                for line in entry.get("name_value", "").splitlines():
                    line = line.strip().lower()
                    if line and "*" not in line:
                        subs.add(line)
            return subs
        except Exception:
            return set()
