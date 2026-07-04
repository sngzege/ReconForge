"""Command-line interface for ReconForge.

Responsibilities:
- Parse command-line arguments
- Dispatch to appropriate commands (scan, list-plugins, etc.)
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
        help="Run reconnaissance scan on a target",
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
    logger.info(f"Starting scan for target: {args.target}")

    try:
        # Load plugins
        from reconforge.core.loader import load_plugins

        plugin_dir = Path(__file__).parent / "plugins"
        registry = load_plugins(plugin_dir)

        if len(registry) == 0:
            logger.warning("No plugins found. Create plugins in the plugins/ directory.")
            print("No plugins found. Create plugins in the plugins/ directory.")
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
            else:
                logger.warning(f"Plugin '{name}' not found, skipping")

        # Run pipeline
        result = pipeline.run(args.target)

        # Print summary
        print(f"\n{'=' * 60}")
        print(f"Scan complete for: {args.target}")
        print(f"{'=' * 60}")
        print(f"Duration: {result.duration.total_seconds():.2f}s")
        print(f"Results: {len(result.results)}")
        print(f"  - Success: {result.success_count}")
        print(f"  - Failed: {result.failure_count}")
        print(f"  - Partial: {result.partial_count}")

        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for error in result.errors[:5]:  # Show first 5 errors
                print(f"  - {error}")
            if len(result.errors) > 5:
                print(f"  ... and {len(result.errors) - 5} more")

        # Print collected data
        all_data = result.get_all_data()
        if all_data:
            print(f"\nCollected {len(all_data)} items:")
            for item in all_data[:20]:  # Show first 20 items
                print(f"  - {item}")
            if len(all_data) > 20:
                print(f"  ... and {len(all_data) - 20} more")

        # Write full report
        try:
            reporter = Reporter(output_dir=config.output_dir)
            report_paths = reporter.write(result)
            report_path = report_paths.get("md", report_paths.get("markdown"))
            if report_path:
                print(f"\nReport written to: {report_path}")
        except Exception as e:
            logger.warning(f"Failed to write report: {e}")

        return 0

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"Error: {e}", file=sys.stderr)
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