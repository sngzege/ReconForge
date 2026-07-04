"""Command-line interface for ReconForge.

Responsibilities:
- Parse command-line arguments
- Dispatch to appropriate commands (scan, discovery, list-plugins, etc.)
- Handle errors gracefully
- Provide helpful help messages

Design:
- Uses argparse for argument parsing
- Subcommands for different operations
- Integrates with Config, Logging, Pipeline, and Plugin Loader
- Returns appropriate exit codes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from collections import defaultdict

from reconforge.core.config import Config, ConfigError, load_config
from reconforge.core.logging_setup import setup_logging
from reconforge.core.pipeline import Pipeline
from reconforge.core.plugin import BasePlugin
from reconforge.reporting.reporter import Reporter


# Discovery-phase plugin names: plugins that perform initial reconnaissance
DISCOVERY_PLUGINS = [
    "normalize_url",
    "dns_resolver",
    "subfinder",
    "crtsh",
    "assetfinder",
    "wayback",
    "whois_lookup",
    "httpx_alive",
    "naabu",
    "merge_engine",
]


def _topo_sort(requires: dict[str, list[str]], names: list[str]) -> list[str]:
    """Topological sort of plugin names by their requires dependencies.

    Args:
        requires: Mapping of plugin name -> list of required upstream plugin names.
        names: Ordered list of plugin names to sort.

    Returns:
        Plugin names in dependency-safe order.
    """
    in_degree: dict[str, int] = {n: 0 for n in names}
    dependents: dict[str, list[str]] = defaultdict(list)

    name_set = set(names)
    for name in names:
        for dep in requires.get(name, []):
            if dep in name_set:
                in_degree[name] += 1
                dependents[dep].append(name)

    queue = [n for n, d in in_degree.items() if d == 0]
    result: list[str] = []

    while queue:
        result.extend(queue)
        next_queue: list[str] = []
        for n in queue:
            for dep in dependents[n]:
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    next_queue.append(dep)
        queue = next_queue

    return result


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for ReconForge CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge - A modular reconnaissance framework",
        epilog="For more information, visit: https://github.com/yourusername/reconforge",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file (default: reconforge.toml)",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override log level from config",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Override output directory from config",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands",
    )

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run full reconnaissance scan on a target",
    )
    scan_parser.add_argument(
        "target",
        help="Target to scan (domain, URL, or IP)",
    )
    scan_parser.add_argument(
        "--plugins",
        nargs="+",
        help="Specific plugins to run (default: all)",
    )
    scan_parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Maximum concurrent workers (default: 10)",
    )

    # discovery command
    disc_parser = subparsers.add_parser(
        "discovery",
        help="Run discovery stage only - enumerate subdomains, ports, and services",
    )
    disc_parser.add_argument(
        "target",
        help="Target to discover (domain, URL, or IP)",
    )
    disc_parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Maximum concurrent workers (default: 10)",
    )

    # list-plugins command
    subparsers.add_parser(
        "list-plugins",
        help="List all available plugins",
    )

    # validate-config command
    subparsers.add_parser(
        "validate-config",
        help="Validate configuration file",
    )

    return parser


def cmd_scan(args: argparse.Namespace, config: Config) -> int:
    """Execute the scan command.

    Args:
        args: Parsed command-line arguments.
        config: Configuration object.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    logger = setup_logging(config, log_dir=Path(config.output_dir) / "logs")

    try:
        # Load plugins
        from reconforge.core.loader import load_plugins

        plugin_dir = Path(__file__).parent / "plugins"
        registry = load_plugins(plugin_dir)

        if len(registry) == 0:
            print("[!] No plugins found.")
            return 0

        # Filter plugins if specified
        plugin_names = args.plugins if args.plugins else registry.get_names()

        # Collect requires for topological sort and pipeline wiring
        plugin_requires: dict[str, list[str]] = {}
        for name in plugin_names:
            if registry.has(name):
                plugin = registry.get(name)
                plugin_requires[name] = list(plugin.requires)

        sorted_names = _topo_sort(plugin_requires, plugin_names)

        # Build pipeline
        pipeline = Pipeline(max_workers=args.max_workers)

        for name in sorted_names:
            if registry.has(name):
                plugin = registry.get(name)
                deps = plugin_requires.get(name, [])
                pipeline.add_plugin(plugin, depends_on=deps)

        # Run pipeline
        print(f"[*] Scanning: {args.target}")
        result = pipeline.run(args.target)

        # Brief summary
        print(f"[+] Done in {result.duration.total_seconds():.1f}s "
              f"| {result.success_count} ok, {result.failure_count} failed")

        # Write report with target name
        try:
            reporter = Reporter(output_dir=config.output_dir)
            report_paths = reporter.write(result, target=args.target)
            report_path = report_paths.get("md", report_paths.get("markdown"))
            if report_path:
                print(f"[+] Report: {report_path}")
        except Exception as e:
            logger.warning(f"Failed to write report: {e}")

        return 0

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


def cmd_discovery(args: argparse.Namespace, config: Config) -> int:
    """Execute the discovery command - enumerate subdomains, ports, services.

    Only runs discovery-phase plugins. Skips tools that are not installed.

    Args:
        args: Parsed command-line arguments.
        config: Configuration object.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    logger = setup_logging(config, log_dir=Path(config.output_dir) / "logs")

    try:
        from reconforge.core.loader import load_plugins

        plugin_dir = Path(__file__).parent / "plugins"
        registry = load_plugins(plugin_dir)

        # Only use discovery plugins that are available
        available = [p for p in DISCOVERY_PLUGINS if registry.has(p)]
        skipped = [p for p in DISCOVERY_PLUGINS if not registry.has(p)]

        if skipped:
            logger.debug(f"Skipping unavailable plugins: {skipped}")

        if not available:
            print("[!] No discovery plugins found.")
            return 1

        # Collect requires for topological sort
        plugin_requires: dict[str, list[str]] = {}
        for name in available:
            plugin = registry.get(name)
            plugin_requires[name] = list(plugin.requires)

        sorted_names = _topo_sort(plugin_requires, available)

        # Build pipeline
        pipeline = Pipeline(max_workers=args.max_workers)

        for name in sorted_names:
            if registry.has(name):
                plugin = registry.get(name)
                deps = plugin_requires.get(name, [])
                pipeline.add_plugin(plugin, depends_on=deps)

        # Run pipeline
        print(f"[*] Discovery: {args.target}")
        result = pipeline.run(args.target)

        # Brief summary
        print(f"[+] Done in {result.duration.total_seconds():.1f}s "
              f"| {result.success_count} ok, {result.failure_count} failed")

        # Write report with target name
        try:
            reporter = Reporter(output_dir=config.output_dir)
            report_paths = reporter.write(result, target=args.target)
            report_path = report_paths.get("md", report_paths.get("markdown"))
            if report_path:
                print(f"[+] Report: {report_path}")
        except Exception as e:
            logger.warning(f"Failed to write report: {e}")

        return 0

    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


def cmd_list_plugins(args: argparse.Namespace, config: Config) -> int:
    """Execute the list-plugins command.

    Args:
        args: Parsed command-line arguments.
        config: Configuration object.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    setup_logging(config)

    try:
        from reconforge.core.loader import load_plugins

        plugin_dir = Path(__file__).parent / "plugins"
        registry = load_plugins(plugin_dir)

        if len(registry) == 0:
            print("No plugins found.")
            print(f"Create plugins in: {plugin_dir}")
            return 0

        print(f"Available plugins ({len(registry)}):\n")
        for plugin in registry.get_all():
            print(f"  {plugin.name}")
            print(f"    Version: {plugin.version}")
            print(f"    Description: {plugin.description}")
            if plugin.requires:
                print(f"    Requires: {', '.join(plugin.requires)}")
            print()

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_validate_config(args: argparse.Namespace, config: Config) -> int:
    """Execute the validate-config command.

    Args:
        args: Parsed command-line arguments.
        config: Configuration object.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    print("Configuration is valid!")
    print(f"\nCurrent configuration:")
    print(f"  thread_count: {config.thread_count}")
    print(f"  timeout: {config.timeout}")
    print(f"  retry_count: {config.retry_count}")
    print(f"  cache_ttl: {config.cache_ttl}")
    print(f"  log_level: {config.log_level}")
    print(f"  output_dir: {config.output_dir}")
    print(f"  rate_limit: {config.rate_limit}")
    return 0


def main() -> None:
    """Entry point for the reconforge CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Load configuration
    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Apply CLI overrides
    # Note: Config is immutable, so we create a new one with overrides
    if args.log_level or args.output_dir:
        from dataclasses import replace

        overrides = {}
        if args.log_level:
            overrides["log_level"] = args.log_level
        if args.output_dir:
            overrides["output_dir"] = str(args.output_dir)
        config = replace(config, **overrides)

    # Dispatch to command handler
    commands = {
        "scan": cmd_scan,
        "discovery": cmd_discovery,
        "list-plugins": cmd_list_plugins,
        "validate-config": cmd_validate_config,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args, config)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()