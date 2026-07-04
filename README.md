# ReconForge

ReconForge is a modular, extensible reconnaissance framework for bug bounty and penetration testing.
It couples a clean stdlib-only Python core with Kali Linux security tools via a dependency-aware plugin pipeline.Tools run concurrently wherever the dep graph allows.

## Quick Start

python -m venv .venv
source .venv/bin/activate
pip install -e .
reconforge --help

## Requirements

- Python 3.11+
- Kali Linux / Debian-based penetration testing distro
- External tools:
  - subfinder, assetfinder (passive subdomain discovery)
  - httpx (HTTP probing, fingerprinting, tech detection)
  - naabu (fast port scanning)
  - nmap (service version detection)
  - katana (web crawling / endpoint discovery)
  - whois (domain registration lookup)
  - gowitness (screenshot capture)


## Reconnaissance Workflow

The pipeline runs plugins in **stages**. Within each stage, independent plugins execute concurrently.
Stages are ordered by the dependency graph declared in each plugin's 
equires attribute.

`
 TARGET INPUT (domain/IP)
        |
        v
 +------+-----------+---------+---------+
 | STAGE 1          |         |         |
 | normalise_url    |  dns    |  whois  |   <-- concurrent within stage
 | (domain* ->      |  resolve|  lookup |
 |  target format)  |         |         |
 +------------------+---------+---------+
        |              |         |
        +------+-------+---------+
               |
               v
 +------+------+------+------+
 | STAGE 2                   |
 | subfinder  |  assetfinder |   <-- concurrent
 | crtsh (cert logs)         |
 +------+------+------+------+
               |
        +------+------+
        |             |
        v             v
 +------+------+  +---+-------+
 | STAGE 3      |  | STAGE 3b  |
 | httpx_alive  |  | naabu     |   <-- concurrent
 | (HTTP probe) |  | (port scan)|
 +------+------+  +-----+-----+
        |               |
        v               v
 +------+------+  +-----+------+
 | STAGE 4a     |  | STAGE 4b   |
 | http_finger  |  | nmap       |   <-- concurrent
 | print        |  | (service   |
 | headers      |  |  version)  |
 | robots.txt   |  |            |
 | sitemap      |  |            |
 | tech_detect  |  |            |
 +------+-------+  +------------+
        |
        v
 +------+------+
 | STAGE 5      |
 | wayback      |   <-- independent
 | katana       |
 | js_discovery |
 | endpoints    |
 | screenshot   |
 +------+-------+
        |
        v
 +------+-------+
 | STAGE 6       |
 | merge_engine  |
 +-------+-------+
         |
         v
 +-------+-------+
 | REPORTING      |
 | JSON  | MD     |
 | HTML  |        |
 +----------------+
`


## Plugin Execution Order

Each plugin declares its upstream dependencies via a class-level 
equires list.
The pipeline resolves these into a directed acyclic graph and executes stages sequentially.
Within a stage all plugins whose dependencies are satisfied run **concurrently** via ThreadPoolExecutor.

| Plugin | Stage | Depends On | External Tool | Concurrent With |
|--------|-------|------------|---------------|-----------------|
| normalize_url | 1 | — | (stdlib) | dns_resolver, whois_lookup |
| dns_resolver | 1 | — | (stdlib) | normalize_url, whois_lookup |
| whois_lookup | 1 | — | whois | normalize_url, dns_resolver |
| subfinder | 2 | normalize_url | subfinder | assetfinder, crtsh |
| assetfinder | 2 | normalize_url | assetfinder | subfinder, crtsh |
| crtsh | 2 | normalize_url | (stdlib urllib) | subfinder, assetfinder |
| httpx_alive | 3b | subdomain results | httpx | naabu |
| naabu | 3a | normalize_url | naabu | httpx_alive |
| http_fingerprint | 4a | httpx_alive | httpx | nmap |
| headers | 4a | httpx_alive | (stdlib urllib) | nmap |
| robots_txt | 4a | httpx_alive | (stdlib urllib) | nmap |
| sitemap | 4a | httpx_alive | (stdlib urllib) | nmap |
| tech_detect | 4a | http_fingerprint | httpx | headers, robots, sitemap |
| nmap | 4b | naabu | nmap | http_fingerprint, headers |
| wayback | 5 | normalize_url | (stdlib urllib) | katana, js_discovery |
| katana | 5 | httpx_alive | katana | wayback, js_discovery |
| js_discovery | 5 | katana | (stdlib re) | wayback, katana |
| endpoints | 5 | katana | (stdlib re) | wayback, screenshot |
| screenshot | 5 | httpx_alive | gowitness | wayback, endpoints |
| merge_engine | 6 | all plugins | (stdlib) | (last stage, single) |

## Tool Parallelism & Sequencing

The framework achieves concurrency at three levels:

**1. Intra-stage concurrency**
Independent plugins within the same stage run in parallel.
Example: Stage 1 runs normalize_url, dns_resolver, and whois_lookup simultaneously.

**2. Inter-stage streaming**
Once a stage completes its results are fed to dependent stages immediately.
The pipeline doesn not wait for unrelated branches — naabu and httpx_alive
(stage 3) can both start as soon as their respective inputs are ready.

**3. External tool subprocess**
Each tool is a child subprocess with its own timeout. The Python framework
is never blocked by a single slow tool across the entire pipeline.

### Tool invocation patterns

- **subprocess tools** (naabu, nmap, subfinder, assetfinder, httpx, katana, whois, gowitness):
  Called via subprocess.run() with stdin input, stdout capture, and explicit timeout.
- **stdlib HTTP tools** (crtsh, wayback, headers, robots_txt, sitemap):
  Use urllib.request.urlopen() — zero Python dependencies, mockable.
- **Parsing-only tools** (js_discovery, endpoints):
  Use stdlib 
e and urllib.parse — no external subprocess.

﻿
## CLI Usage

Common commands:

```bash
reconforge scan example.com
reconforge scan example.com --plugins dns_resolver,naabu,nmap
reconforge list-plugins
reconforge validate-config
reconforge --version
```

Useful flags:
- `--config` - path to custom TOML config
- `--log-level` - override logging level (DEBUG, INFO, WARNING)
- `--output-dir` - custom output directory
- `--max-workers` - concurrency limit for the thread pool

## Project Structure

```
src/reconforge/
  cli.py
  core/          (stdlib-only core)
  plugins/       (20 plugins)
  reporting/     (JSON, MD, HTML + screenshot provider)
tests/
  plugins/       (per-plugin unit tests)
```

## Configuration

Example reconforge.toml:

```toml
thread_count = 10
timeout = 300
retry_count = 1
log_level = "INFO"
output_dir = "artifacts"
rate_limit = 0
```

## Adding a Plugin

1. Create a .py file in src/reconforge/plugins/.
2. Subclass BasePlugin with name, description, requires, run().
3. Return Result via factory helpers.
4. Add unit tests in tests/plugins/.
No core changes required.

## Testing

```bash
pytest -m "not integration"    # unit tests only
pytest                         # all tests
```

## Reporting

The Reporter produces three formats from a single PipelineResult:
- JSON - machine-readable with all plugin data
- Markdown - human-readable summary with timeline
- HTML - standalone styled report

Artifacts: artifacts/reports/ and artifacts/screenshots/

## Security

- This framework automates security tooling for authorised assessments only.
- Scope compliance remains the operator responsibility.
- Some plugins make external network requests; review network policy before running.
