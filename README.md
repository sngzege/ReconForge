# ReconForge

ReconForge is a modular, extensible reconnaissance framework for bug bounty and penetration testing workflows. It focuses on clean architecture, plugin isolation, and a stdlib-first core while orchestrating standard security tools through a well-defined plugin interface.

## Quick Start

python -m venv .venv
source .venv/bin/activate
pip install -e .
reconforge --help

## Requirements

- Python 3.11+
- Recommended OS: Kali Linux or Debian-based penetration testing distro
- External tools: subfinder, assetfinder, httpx, naabu, nmap, katana, whois, gowitness

## CLI Usage

reconforge scan example.com
reconforge scan example.com --plugins dns_resolver,naabu,nmap
reconforge list-plugins
reconforge validate-config

## Architecture

- Core: stdlib-only framework code.
- Plugins: lifecycle-based tool integrations.
- Pipeline: dependency-aware scheduling.
- Reporting: JSON, Markdown, and HTML outputs.


# ReconForge

ReconForge is a modular, extensible reconnaissance framework for bug bounty and penetration testing workflows.