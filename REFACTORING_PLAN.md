"""Refactoring Main"

<persona>
You are a Senior Software Architect refactoring the ReconForge reconnaissance framework.
</persona>

<instruction>
You will create a structured refactoring plan by breaking down the project according to the Plugin Architectures and Pipeline Orchestration guidelines.

Follow the "refactoring_main" workflow:
1. Understand requirements
2. Decompose the system into modules
3. Identify files to create
4. Specify each file's purpose and architecture
5. Define dependencies
6. List the specific refactoring steps needed
</instruction>

<refactoring_main>
Initial analysis shows the current ReconForge architecture has several limitations:
- Plugin architecture is simple but fragile - a single failing external tool breaks the entire pipeline
- Direct dependency handling lacks flexibility - plugins crash if any upstream dependency fails
- No granular error handling - only binary success/failure states
- Poor terminal UX - verbose error messages
- Limited tool management - ToolResolver is good but used directly by plugins

Goal: Transform into a resilient, capability-based pipeline with graceful degradation.

Essential modules needed:
- Core module: tool_provider.py (new), plugin.py, pipeline.py (updated), result.py (updated), scheduler.py (updated), loader.py (updated), config.py (existing), logging_setup.py (existing)
- Plugins module: httpx_alive.py (updated), wayback.py (new), subfinder.py (new), assetfinder.py (new), crtsh.py (new), dns_resolver.py (new), nmap.py (new), naabu.py (new), katana.py (new), merge_engine.py (updated), html_reporter.py (new)
- Reporting module: json_reporter.py (new), markdown_reporter.py (new), html_reporter.py (new), statistics.py (new), timeline.py (new), reporter.py (new)
- Tests module: tests for each new architecture component

File dependency graph:
- plugin.py -> tool_provider.py, result.py, execute_plugin_safely
- pipeline.py -> tool_provider.py (NEW), plugin.py, result.py
- httpx_alive.py -> tool_provider.py (NEW), result.py, tool_resolver.py (updated to integrate with provider)
- Each new plugin -> tool_provider.py (NEW), result.py
- All new modules -> pipeline.py
- reporter.py -> result.py, statistics.py, timeline.py
- Existing modules remain unchanged in their basic structure but get updated to use new architecture

This requires 3-4 days of focused work. Let's start with the architectural components.
</refactoring_main>
