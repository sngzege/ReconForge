"""HTTP alive check plugin for ReconForge.

Responsibilities:
- Check which subdomains/hosts are HTTP-accessible
- Return list of alive URLs with status codes
- Filter dead hosts before deeper scanning

Design:
- Uses curl for HTTP checks
- Checks both HTTPS and HTTP
- Depends on normalize_url and subdomain_scan
"""

from __future__ import annotations

import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class HttpAlivePlugin(BasePlugin):
    """Check HTTP accessibility of hosts."""

    requires: ClassVar[list[str]] = ["normalize_url", "subdomain_scan"]

    @property
    def name(self) -> str:
        return "http_alive"

    @property
    def description(self) -> str:
        return "Check HTTP accessibility using curl"

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

        # Build host list: main domain + subdomains
        hosts = [domain]
        subdomain_result = upstream_results.get("subdomain_scan")
        if subdomain_result and subdomain_result.is_success and subdomain_result.data:
            for sub in subdomain_result.data:
                if sub != domain:
                    hosts.append(sub)

        # Build URLs to check
        urls_to_check = []
        for host in hosts:
            if is_ip and host == domain:
                urls_to_check.append(f"http://{host}")
            else:
                urls_to_check.append(f"https://{host}")
                urls_to_check.append(f"http://{host}")

        alive_urls = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._check_url, url): url
                for url in urls_to_check
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_urls.append(result)

        # Sort by URL
        alive_urls.sort(key=lambda x: x["url"])

        return create_success_result(
            module=self.name,
            data=alive_urls,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"checked": len(urls_to_check), "alive": len(alive_urls)},
        )

    def _check_url(self, url: str) -> dict | None:
        """Check if URL is alive."""
        try:
            proc = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}",
                 "-L", "--max-time", "5", "-k", url],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                return None

            parts = proc.stdout.strip().split("|")
            if len(parts) < 2:
                return None

            status_code = int(parts[0])
            size = int(parts[1])

            # Consider alive if we get any HTTP response
            if status_code > 0:
                return {
                    "url": url,
                    "status_code": status_code,
                    "size": size,
                }
            return None
        except Exception:
            return None
