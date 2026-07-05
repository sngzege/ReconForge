"""JavaScript analysis plugin for ReconForge.

Responsibilities:
- Find JavaScript files on target
- Extract secrets, API keys, endpoints from JS files
- Identify interesting patterns

Design:
- Uses curl to fetch pages and JS files
- Regex-based pattern matching for secrets
- Depends on http_alive for target URLs
"""

from __future__ import annotations

import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


# Patterns to search for in JS files
SECRET_PATTERNS = [
    # API Keys
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_key"),
    (r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_key"),
    (r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_secret"),
    
    # AWS
    (r'AKIA[0-9A-Z]{16}', "aws_access_key"),
    (r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "aws_secret"),
    
    # Google
    (r'AIza[0-9A-Za-z_\-]{35}', "google_api_key"),
    
    # GitHub
    (r'ghp_[0-9a-zA-Z]{36}', "github_token"),
    (r'github[_-]?token\s*[:=]\s*["\']([a-zA-Z0-9_\-]{36,})["\']', "github_token"),
    
    # Slack
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "slack_token"),
    
    # Generic secrets
    (r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "secret"),
    (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "password"),
    (r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "password"),
    
    # Internal URLs
    (r'https?://[a-zA-Z0-9.-]+\.(internal|local|corp|private)(:[0-9]+)?(/[a-zA-Z0-9/._-]*)?', "internal_url"),
    (r'https?://(10\.[0-9.]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9.]+|192\.168\.[0-9.]+)(:[0-9]+)?(/[a-zA-Z0-9/._-]*)?', "internal_ip"),
    
    # Endpoints
    (r'["\']?/api/[a-zA-Z0-9/._-]+["\']?', "api_endpoint"),
    (r'["\']?/v[123]/[a-zA-Z0-9/._-]+["\']?', "api_endpoint"),
]


class JsAnalyzePlugin(BasePlugin):
    """Analyze JavaScript files for secrets and endpoints."""

    requires: ClassVar[list[str]] = ["http_alive"]

    @property
    def name(self) -> str:
        return "js_analyze"

    @property
    def description(self) -> str:
        return "Analyze JS files for secrets and endpoints"

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

        # Use first alive URL
        base_url = alive_urls[0]["url"]

        # Find JS files
        js_urls = self._find_js_files(base_url)

        # Analyze JS files for secrets
        all_findings = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self._analyze_js, js_url): js_url
                for js_url in js_urls[:10]  # Limit to 10 JS files
            }
            for future in as_completed(futures):
                findings = future.result()
                all_findings.extend(findings)

        return create_success_result(
            module=self.name,
            data=all_findings,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"js_files_checked": len(js_urls[:10]), "findings": len(all_findings)},
        )

    def _find_js_files(self, url: str) -> list[str]:
        """Find JavaScript file URLs from page HTML."""
        try:
            proc = subprocess.run(
                ["curl", "-s", "-L", "--max-time", "10", "-k", url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0:
                return []

            html = proc.stdout
            js_urls = []

            # Find <script src="..."> tags
            script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
            for match in re.finditer(script_pattern, html, re.IGNORECASE):
                src = match.group(1)
                # Convert relative URLs to absolute
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    src = f"{parsed.scheme}://{parsed.netloc}{src}"
                elif not src.startswith("http"):
                    src = url.rstrip("/") + "/" + src
                js_urls.append(src)

            return list(set(js_urls))
        except Exception:
            return []

    def _analyze_js(self, js_url: str) -> list[dict]:
        """Analyze a JS file for secrets."""
        try:
            proc = subprocess.run(
                ["curl", "-s", "-L", "--max-time", "10", "-k", js_url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0:
                return []

            js_content = proc.stdout
            findings = []

            for pattern, finding_type in SECRET_PATTERNS:
                for match in re.finditer(pattern, js_content, re.IGNORECASE):
                    value = match.group(1) if match.lastindex else match.group(0)
                    # Skip common false positives
                    if value.lower() in ["example", "test", "placeholder", "your_api_key"]:
                        continue
                    findings.append({
                        "js_url": js_url,
                        "type": finding_type,
                        "value": value[:50] + "..." if len(value) > 50 else value,
                    })

            return findings
        except Exception:
            return []
