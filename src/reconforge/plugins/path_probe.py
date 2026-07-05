"""Path and sensitive file probe plugin for ReconForge.

Responsibilities:
- Probe common directories and sensitive files using curl
- Detect interesting responses (200, 301, 302, 403)
- Filter and report meaningful findings

Design:
- Uses curl for HTTP requests
- Checks common paths like /robots.txt, /sitemap.xml, /.git, etc.
- Depends on normalize_url for target URL
"""

from __future__ import annotations

import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


# Common paths and sensitive files to probe
SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.bash_history",
    "/.sh_history",
    "/.htaccess",
    "/.htpasswd",
    "/wp-admin",
    "/wp-login.php",
    "/admin",
    "/login",
    "/phpmyadmin",
    "/server-status",
    "/server-info",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/api",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/.vscode/sftp.json",
    "/backup.zip",
    "/db.sql",
    "/dump.sql",
    "/config.php",
    "/web.config",
]


class PathProbePlugin(BasePlugin):
    """Probe common paths and sensitive files."""

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        return "path_probe"

    @property
    def description(self) -> str:
        return "Probe common paths and sensitive files using curl"

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

        # Build base URL
        if is_ip:
            base_url = f"http://{domain}"
        else:
            base_url = f"https://{domain}"

        findings = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._probe_path, base_url, path): path
                for path in SENSITIVE_PATHS
            }
            for future in as_completed(futures):
                path = futures[future]
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                except Exception:
                    pass

        # Sort by status code priority (interesting ones first)
        priority = {200: 0, 301: 1, 302: 2, 403: 3}
        findings.sort(key=lambda x: priority.get(x["status_code"], 99))

        return create_success_result(
            module=self.name,
            data=findings,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"domain": domain, "count": len(findings), "paths_checked": len(SENSITIVE_PATHS)},
        )

    def _probe_path(self, base_url: str, path: str) -> dict | None:
        """Probe a single path and return finding if interesting."""
        url = f"{base_url}{path}"
        try:
            proc = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}|%{redirect_url}", 
                 "-L", "--max-time", "5", url],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                return None

            parts = proc.stdout.strip().split("|")
            if len(parts) < 3:
                return None

            status_code = int(parts[0])
            size = int(parts[1])
            redirect_url = parts[2]

            # Filter: only interesting responses
            if status_code in [200, 301, 302, 403]:
                # Skip if size is too small (likely empty)
                if status_code == 200 and size < 100:
                    return None

                return {
                    "url": url,
                    "path": path,
                    "status_code": status_code,
                    "size": size,
                    "redirect_url": redirect_url if redirect_url else None,
                }
            return None
        except Exception:
            return None
