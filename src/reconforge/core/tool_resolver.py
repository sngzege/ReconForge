"""Tool resolver for verifying external security tools.

Responsibilities:
- Confirm required external tools are present on PATH
- Verify ProjectDiscovery tools are the *correct* binary (not a
  name-shadowing imposter such as the Python httpx CLI) by probing a
  vendor marker in the tool's banner
- Raise a clear ToolUnavailableError when a tool is missing or is the
  wrong binary, so plugins fail with an actionable message instead of
  cryptic subprocess flag errors

Design:
- Registry of per-tool signatures (vendor + expected output markers)
- Tools without a registered signature fall back to a presence-only check
- Successful resolutions are cached on the class so repeated resolve()
  calls within one pipeline run do not re-probe the same binary
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import ClassVar


class ToolUnavailableError(RuntimeError):
    """Raised when a required external tool is missing or is the wrong binary."""


@dataclass(frozen=True)
class ToolSignature:
    """Identity signature for an external tool.

    Attributes:
        vendor: Human-readable vendor name used in error messages.
        markers: Case-insensitive substrings expected in the tool's
            banner/version output. All must be present for the binary
            to be accepted as the correct tool.
        install_url: Where to install the correct tool from.
    """

    vendor: str
    markers: tuple[str, ...]
    install_url: str


class ToolResolver:
    """Verify external security tools are the correct binaries before use.

    Detects cases where a name-shadowing binary (e.g. the Python httpx CLI
    installed via pip instead of projectdiscovery httpx) is on PATH, and
    raises a clear ToolUnavailableError rather than letting plugins fail
    cryptically at runtime with incompatible CLI flags.
    """

    _SIGNATURES: ClassVar[dict[str, ToolSignature]] = {
        "httpx": ToolSignature(
            vendor="projectdiscovery",
            markers=("projectdiscovery",),
            install_url="https://github.com/projectdiscovery/httpx",
        ),
        "naabu": ToolSignature(
            vendor="projectdiscovery",
            markers=("projectdiscovery",),
            install_url="https://github.com/projectdiscovery/naabu",
        ),
        "katana": ToolSignature(
            vendor="projectdiscovery",
            markers=("projectdiscovery",),
            install_url="https://github.com/projectdiscovery/katana",
        ),
        "subfinder": ToolSignature(
            vendor="projectdiscovery",
            markers=("projectdiscovery",),
            install_url="https://github.com/projectdiscovery/subfinder",
        ),
        "nmap": ToolSignature(
            vendor="nmap.org",
            markers=("nmap",),
            install_url="https://nmap.org",
        ),
    }

    _cache: ClassVar[dict[str, str]] = {}

    def resolve(self, name: str) -> str:
        """Resolve and verify a tool, returning its absolute path.

        Args:
            name: Tool executable name (e.g. "httpx").

        Returns:
            Absolute path to the verified executable.

        Raises:
            ToolUnavailableError: If the tool is missing from PATH or is
                present but does not appear to be the expected binary.
        """
        if name in ToolResolver._cache:
            return ToolResolver._cache[name]

        path = shutil.which(name)
        if path is None:
            sig = ToolResolver._SIGNATURES.get(name)
            hint = (
                f"Install the correct {sig.vendor} tool from: {sig.install_url}"
                if sig
                else f"Install '{name}' and ensure it is on PATH."
            )
            raise ToolUnavailableError(
                f"{name} is not installed or not in PATH. {hint}"
            )

        sig = ToolResolver._SIGNATURES.get(name)
        if sig is not None:
            output = self._probe(name)
            lowered = output.lower()
            if not all(marker.lower() in lowered for marker in sig.markers):
                raise ToolUnavailableError(
                    f"'{name}' is installed at {path} but does not appear to be "
                    f"the expected {sig.vendor} binary (probe output did not "
                    f"contain {sig.markers}). A different program may be "
                    f"shadowing it on PATH. Install the correct tool from: "
                    f"{sig.install_url}"
                )

        ToolResolver._cache[name] = path
        return path

    @staticmethod
    def _probe(name: str) -> str:
        """Probe a tool's banner/version output for identity markers.

        Runs the tool with no arguments and a closed stdin so banner-only
        tools exit promptly. Returns combined stdout+stderr.

        Args:
            name: Tool executable name.

        Returns:
            Combined captured output, or empty string on probe failure.
        """
        try:
            proc = subprocess.run(
                [name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the shared resolution cache (intended for testing)."""
        cls._cache.clear()
