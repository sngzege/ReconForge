"""Markdown reporter for ReconForge.

Produces merged findings report - human-readable summary of all discoveries.
"""

from __future__ import annotations

from reconforge.core.pipeline import PipelineResult


def to_markdown(result: PipelineResult) -> str:
    """Render PipelineResult as merged findings Markdown report."""
    lines: list[str] = [
        "# ReconForge Discovery Report",
        "",
        f"**Duration:** {result.duration.total_seconds():.2f}s",
        f"**Plugins:** {result.success_count}/{len(result.results)} successful",
        "",
    ]

    # Collect data by category
    target_info = {}
    subdomains = []
    alive_hosts = []
    open_ports = []
    technologies = []
    waf_info = []
    ssl_certs = []
    discovered_paths = []
    js_secrets = []
    sensitive_paths = []

    for r in result.results:
        if r.module == "normalize_url" and r.data:
            target_info["domain"] = r.data
            target_info["is_ip"] = r.metadata.get("is_ip", False)
        elif r.module == "dns_resolver" and r.is_success and r.data:
            target_info["ips"] = r.data
        elif r.module == "subdomain_scan" and r.is_success and r.data:
            subdomains = r.data
        elif r.module == "http_alive" and r.is_success and r.data:
            alive_hosts = r.data
        elif r.module == "port_scan" and r.is_success and r.data:
            open_ports = r.data
        elif r.module == "tech_scan" and r.is_success and r.data:
            technologies = r.data
        elif r.module == "waf_detect" and r.is_success and r.data:
            waf_info = r.data
        elif r.module == "ssl_info" and r.is_success and r.data:
            ssl_certs = r.data
        elif r.module == "dir_brute" and r.is_success and r.data:
            discovered_paths = r.data
        elif r.module == "js_analyze" and r.is_success and r.data:
            js_secrets = r.data
        elif r.module == "path_probe" and r.is_success and r.data:
            sensitive_paths = r.data

    # Target
    lines.append("## Target")
    lines.append("")
    if "domain" in target_info:
        lines.append(f"- **Domain:** {target_info['domain']}")
    if "ips" in target_info:
        lines.append(f"- **IPs:** {', '.join(target_info['ips'])}")
    lines.append("")

    # SSL Certificate
    if ssl_certs:
        lines.append("## SSL Certificate")
        lines.append("")
        cert = ssl_certs[0]
        lines.append(f"- **Subject:** {cert.get('subject', '')}")
        lines.append(f"- **Issuer:** {cert.get('issuer', '')} ({cert.get('issuer_cn', '')})")
        lines.append(f"- **Valid:** {cert.get('not_before', '')} → {cert.get('not_after', '')}")
        sans = cert.get("sans", [])
        if sans:
            lines.append(f"- **SANs:** {', '.join(sans)}")
        lines.append("")

    # WAF
    if waf_info:
        lines.append("## WAF Detection")
        lines.append("")
        for w in waf_info:
            if w.get("waf_detected"):
                lines.append(f"- ⚠ **WAF Detected:** {w.get('waf_name', 'Unknown')}")
            else:
                lines.append("- ✓ No WAF detected")
        lines.append("")

    # Subdomains
    if subdomains:
        lines.append(f"## Subdomains ({len(subdomains)})")
        lines.append("")
        for sub in subdomains:
            lines.append(f"- {sub}")
        lines.append("")

    # Alive Hosts
    if alive_hosts:
        lines.append(f"## Alive Hosts ({len(alive_hosts)})")
        lines.append("")
        lines.append("| Status | URL | Size |")
        lines.append("|--------|-----|------|")
        for h in alive_hosts:
            lines.append(f"| {h.get('status_code', '')} | {h.get('url', '')} | {h.get('size', '')} bytes |")
        lines.append("")

    # Open Ports
    if open_ports:
        lines.append(f"## Open Ports ({len(open_ports)})")
        lines.append("")
        lines.append("| Host | Port | Service | Product | Version |")
        lines.append("|------|------|---------|---------|---------|")
        for p in open_ports:
            lines.append(
                f"| {p.get('host', '')} | {p.get('port', '')} "
                f"| {p.get('service', '')} | {p.get('product', '')} "
                f"| {p.get('version', '')} |"
            )
        lines.append("")

    # Technologies
    if technologies:
        lines.append(f"## Technologies ({len(technologies)})")
        lines.append("")
        tech_by_type: dict[str, list[str]] = {}
        for tech in technologies:
            t = tech.get("type", "Unknown")
            v = tech.get("value", "")
            if v and v != "detected":
                tech_by_type.setdefault(t, []).append(v)
        for t, vals in sorted(tech_by_type.items()):
            lines.append(f"- **{t}:** {', '.join(sorted(set(vals)))}")
        lines.append("")

    # Discovered Paths
    if discovered_paths:
        lines.append(f"## Discovered Paths ({len(discovered_paths)})")
        lines.append("")
        lines.append("| Status | URL | Size |")
        lines.append("|--------|-----|------|")
        for p in discovered_paths:
            lines.append(
                f"| {p.get('status_code', '')} "
                f"| {p.get('url', '')} "
                f"| {p.get('size', '')} bytes |"
            )
        lines.append("")

    # JS Secrets
    if js_secrets:
        lines.append(f"## JS Secrets/Endpoints ({len(js_secrets)})")
        lines.append("")
        lines.append("| Type | Value | Source |")
        lines.append("|------|-------|--------|")
        for s in js_secrets:
            lines.append(
                f"| {s.get('type', '')} "
                f"| {s.get('value', '')} "
                f"| {s.get('js_url', '')} |"
            )
        lines.append("")

    # Sensitive Paths
    if sensitive_paths:
        lines.append(f"## Sensitive Paths ({len(sensitive_paths)})")
        lines.append("")
        lines.append("| Status | URL | Size |")
        lines.append("|--------|-----|------|")
        for p in sensitive_paths:
            lines.append(
                f"| {p.get('status_code', '')} "
                f"| {p.get('url', '')} "
                f"| {p.get('size', '')} bytes |"
            )
        lines.append("")

    return "\n".join(lines)
