"""Directory brute force plugin for ReconForge.

Responsibilities:
- Discover hidden directories and files using wordlist
- Stealth mode: low rate to avoid triggering alarms

Design:
- Uses gobuster with conservative settings
- Small wordlist, low threads, delay between requests
- Depends on http_alive for target URLs
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


# Conservative wordlist for stealth mode
STEALTH_WORDLIST = """admin
login
wp-admin
wp-login.php
api
swagger
swagger.json
openapi.json
graphql
phpmyadmin
test
dev
staging
backup
config
.git
.env
robots.txt
sitemap.xml
server-status
server-info
.well-known/security.txt
dashboard
console
panel
manager
status
health
metrics
info
docs
api-docs
v1
v2
v3
internal
private
public
assets
static
uploads
images
css
js
"""


class DirBrutePlugin(BasePlugin):
    """Directory brute force with stealth settings."""

    requires: ClassVar[list[str]] = ["http_alive"]

    @property
    def name(self) -> str:
        return "dir_brute"

    @property
    def description(self) -> str:
        return "Stealth directory brute force using gobuster"

    def setup(self, **kwargs: object) -> None:
        if shutil.which("gobuster") is None:
            raise RuntimeError(
                "gobuster is not installed. Install with: apt install gobuster"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        start = time.perf_counter()

        http_alive_result = upstream_results.get("http_alive")
        if not http_alive_result or not http_alive_result.is_success:
            return create_failure_result(
                module=self.name,
                error="http_alive result not available or failed",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        alive_urls = http_alive_result.data
        if not alive_urls:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        # Use first alive URL (main domain)
        base_url = alive_urls[0]["url"]

        # Create temp wordlist file
        wordlist_path = Path("/tmp/reconforge_wordlist.txt")
        wordlist_path.write_text(STEALTH_WORDLIST)

        findings = self._run_gobuster(base_url, wordlist_path)

        # Cleanup
        try:
            wordlist_path.unlink()
        except Exception:
            pass

        return create_success_result(
            module=self.name,
            data=findings,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"base_url": base_url, "count": len(findings), "mode": "stealth"},
        )

    def _run_gobuster(self, url: str, wordlist: Path) -> list[dict]:
        """Run gobuster with stealth settings."""
        try:
            # Stealth settings: 1 thread, 0.5s delay, small wordlist
            proc = subprocess.run(
                ["gobuster", "dir", "-u", url, "-w", str(wordlist),
                 "-t", "1", "--delay", "500ms",
                 "-q", "--no-progress", "-r",
                 "-o", "/dev/stdout"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            findings = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("==="):
                    continue

                # Parse gobuster output: "path (Status: 200) [Size: 1234]"
                if "(Status:" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        path = parts[0]
                        status = ""
                        size = ""
                        for i, p in enumerate(parts):
                            if p == "(Status:":
                                status = parts[i+1].rstrip(")")
                            if p == "[Size:":
                                size = parts[i+1].rstrip("]")
                        findings.append({
                            "path": path,
                            "url": f"{url.rstrip('/')}/{path.lstrip('/')}",
                            "status_code": int(status) if status.isdigit() else 0,
                            "size": int(size) if size.isdigit() else 0,
                        })
            return findings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
