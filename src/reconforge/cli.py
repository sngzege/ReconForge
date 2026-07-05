"""Command-line interface for ReconForge.

Simple CLI for discovery reconnaissance:
- reconforge scan <target> - Run full discovery scan
- reconforge --help - Show help
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reconforge.core.config import Config, ConfigError, load_config
from reconforge.core.logging_setup import setup_logging
from reconforge.core.pipeline import Pipeline
from reconforge.core.loader import load_plugins
from reconforge.reporting.reporter import Reporter


def cmd_scan(args: argparse.Namespace, config: Config) -> int:
    """Run discovery scan on target."""
    setup_logging(config)
    
    target = args.target
    print(f"\n[*] Starting ReconForge scan on: {target}\n")
    
    # Load plugins
    plugin_dir = Path(__file__).parent / "plugins"
    registry = load_plugins(plugin_dir)
    
    if len(registry) == 0:
        print("[!] No plugins found.")
        return 1
    
    # Build pipeline
    pipeline = Pipeline(max_workers=config.thread_count)
    
    # Add plugins in dependency order
    plugin_names = [
        "normalize_url",
        "dns_resolver",
        "ssl_info",
        "subdomain_scan",
        "http_alive",
        "port_scan",
        "tech_scan",
        "waf_detect",
        "dir_brute",
        "js_analyze",
        "path_probe",
    ]
    
    for name in plugin_names:
        plugin = registry.get(name)
        if plugin:
            pipeline.add_plugin(plugin, depends_on=plugin.requires)
    
    # Run pipeline
    print("[*] Running discovery pipeline...\n")
    result = pipeline.run(target)
    
    # Print merged results to terminal
    _print_merged_results(result)
    
    # Write reports
    reporter = Reporter(config.output_dir)
    paths = reporter.write(result, target)
    
    print(f"\n[*] Reports written to:")
    for fmt, path in paths.items():
        print(f"    {fmt}: {path}")
    
    return 0


def _print_merged_results(result) -> None:
    """Print merged and meaningful results to terminal."""
    print("=" * 70)
    print("RECONFORGE DISCOVERY REPORT")
    print("=" * 70)
    
    # Collect all data by category
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
    
    # TARGET INFO
    print("\n[TARGET INFO]")
    if "domain" in target_info:
        print(f"  Domain: {target_info['domain']}")
    if "ips" in target_info:
        print(f"  IPs: {', '.join(target_info['ips'])}")
    
    # SSL CERT
    if ssl_certs:
        print("\n[SSL CERTIFICATE]")
        cert = ssl_certs[0]
        print(f"  Subject: {cert.get('subject', '')}")
        print(f"  Issuer: {cert.get('issuer', '')} ({cert.get('issuer_cn', '')})")
        print(f"  Valid: {cert.get('not_before', '')} -> {cert.get('not_after', '')}")
        sans = cert.get("sans", [])
        if sans:
            print(f"  SANs: {', '.join(sans[:10])}")
            if len(sans) > 10:
                print(f"  ... and {len(sans) - 10} more SANs")
    
    # SUBDOMAINS
    if subdomains:
        print(f"\n[SUBDOMAINS] ({len(subdomains)} found)")
        for idx, sub in enumerate(subdomains[:20], 1):
            print(f"  {idx}. {sub}")
        if len(subdomains) > 20:
            print(f"  ... and {len(subdomains) - 20} more")
    
    # ALIVE HOSTS
    if alive_hosts:
        print(f"\n[ALIVE HOSTS] ({len(alive_hosts)} responding)")
        for idx, host in enumerate(alive_hosts[:15], 1):
            print(f"  {idx}. [{host.get('status_code', 0)}] {host.get('url', '')} ({host.get('size', 0)} bytes)")
        if len(alive_hosts) > 15:
            print(f"  ... and {len(alive_hosts) - 15} more")
    
    # WAF
    if waf_info:
        print("\n[WAF DETECTION]")
        for w in waf_info:
            if w.get("waf_detected"):
                print(f"  ⚠ WAF Detected: {w.get('waf_name', 'Unknown')}")
            else:
                print(f"  ✓ No WAF detected")
    
    # OPEN PORTS
    if open_ports:
        print(f"\n[OPEN PORTS] ({len(open_ports)} found)")
        for idx, port_info in enumerate(open_ports[:20], 1):
            host = port_info.get("host", "")
            port = port_info.get("port", 0)
            service = port_info.get("service", "")
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            line = f"  {idx}. {host}:{port}"
            if service:
                line += f" ({service}"
                if product:
                    line += f" - {product}"
                    if version:
                        line += f" {version}"
                line += ")"
            print(line)
        if len(open_ports) > 20:
            print(f"  ... and {len(open_ports) - 20} more")
    
    # TECHNOLOGIES
    if technologies:
        print(f"\n[TECHNOLOGIES] ({len(technologies)} detected)")
        tech_by_type = {}
        for tech in technologies:
            tech_type = tech.get("type", "Unknown")
            tech_value = tech.get("value", "")
            if tech_type not in tech_by_type:
                tech_by_type[tech_type] = []
            if tech_value and tech_value != "detected":
                tech_by_type[tech_type].append(tech_value)
        for tech_type, values in sorted(tech_by_type.items()):
            if values:
                unique_vals = list(set(values))
                print(f"  {tech_type}: {', '.join(unique_vals[:5])}")
    
    # DISCOVERED PATHS (dir_brute)
    if discovered_paths:
        print(f"\n[DISCOVERED PATHS] ({len(discovered_paths)} found)")
        for idx, p in enumerate(discovered_paths[:20], 1):
            print(f"  {idx}. [{p.get('status_code', 0)}] {p.get('url', '')} ({p.get('size', 0)} bytes)")
        if len(discovered_paths) > 20:
            print(f"  ... and {len(discovered_paths) - 20} more")
    
    # JS SECRETS
    if js_secrets:
        print(f"\n[JS SECRETS/ENDPOINTS] ({len(js_secrets)} found)")
        for idx, s in enumerate(js_secrets[:20], 1):
            print(f"  {idx}. [{s.get('type', '')}] {s.get('value', '')} (in {s.get('js_url', '')})")
        if len(js_secrets) > 20:
            print(f"  ... and {len(js_secrets) - 20} more")
    
    # SENSITIVE PATHS (path_probe)
    if sensitive_paths:
        print(f"\n[SENSITIVE PATHS] ({len(sensitive_paths)} found)")
        for idx, p in enumerate(sensitive_paths[:20], 1):
            print(f"  {idx}. [{p.get('status_code', 0)}] {p.get('url', '')} ({p.get('size', 0)} bytes)")
        if len(sensitive_paths) > 20:
            print(f"  ... and {len(sensitive_paths) - 20} more")
    
    # SUMMARY
    print("\n" + "=" * 70)
    print(f"Total duration: {result.duration.total_seconds():.2f}s")
    print(f"Successful plugins: {result.success_count}/{len(result.results)}")
    print("=" * 70)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge - Simple discovery reconnaissance tool",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.3.0",
    )
    
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to config file (default: reconforge.toml)",
    )
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for reports",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run discovery scan")
    scan_parser.add_argument("target", help="Target domain, URL, or IP")
    
    return parser


def main() -> None:
    """Entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    # Load config
    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"[!] Config error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Apply CLI overrides
    if args.output_dir:
        from dataclasses import replace
        config = replace(config, output_dir=str(args.output_dir))
    
    # Dispatch
    if args.command == "scan":
        exit_code = cmd_scan(args, config)
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
