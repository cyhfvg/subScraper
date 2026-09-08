#!/usr/bin/env python3
"""
Recon Orchestrator

Features:
- Input: TLD / domain
- Tools: amass, ffuf, httpx, nuclei, nikto
- Auto-install (best effort) if tools are missing
- Optional Amass API key setup on first run
- Subdomain enumeration (amass + ffuf brute)
- Dedup + stateful JSON DB for progress/resume
- HTTP probing (httpx)
- Vuln scanning (nuclei, nikto)
- One shared HTML dashboard updated every N seconds
- Safe to run multiple times concurrently on the same machine
"""

