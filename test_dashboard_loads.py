#!/usr/bin/env python3
"""
Dashboard JS is split under web/static/js. Concatenate in manifest order and
execute against a DOM stub so a load-time error still fails CI.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

with patch('main.ensure_dirs'), \
     patch('main.init_database'), \
     patch('main.migrate_json_to_sqlite'):
    import main  # noqa: E402

SMOKE_SCRIPT = Path(__file__).parent / "tools" / "dashboard_smoke.js"
JS_DIR = Path(__file__).parent / "web" / "static" / "js"


def extract_dashboard_script() -> str:
    manifest = (JS_DIR / "manifest.txt").read_text(encoding="utf-8").splitlines()
    chunks = []
    for name in manifest:
        name = name.strip()
        if not name:
            continue
        chunks.append((JS_DIR / name).read_text(encoding="utf-8"))
    assert chunks, "no dashboard javascript found"
    return "\n".join(chunks)



@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_script_loads_without_runtime_errors():
    """
    Catches the class of bug that only shows up in a browser: using a const
    before its declaration, calling an undefined function at load time, and
    similar. `node --check` parses but never executes, so it misses these.
    """
    assert SMOKE_SCRIPT.exists(), f"missing smoke harness at {SMOKE_SCRIPT}"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(extract_dashboard_script())
        script_path = handle.name
    try:
        result = subprocess.run(["node", str(SMOKE_SCRIPT), script_path],
                                capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, (
        "dashboard script failed to load:\n"
        + (result.stderr or result.stdout).strip()
    )


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_script_parses():
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(extract_dashboard_script())
        script_path = handle.name
    try:
        result = subprocess.run(["node", "--check", script_path],
                                capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, result.stderr


def test_every_referenced_view_has_a_section():
    """Each nav link must point at a section that exists."""
    views = set(re.findall(r'class="nav-link" data-view="([a-z-]+)"', main.INDEX_HTML))
    sections = set(re.findall(r'<section class="module" data-view="([a-z-]+)"', main.INDEX_HTML))
    assert views, "no nav links found"
    assert views <= sections, f"nav links without a section: {sorted(views - sections)}"


def test_index_uses_single_dashboard_bundle():
    """Separate <script> tags break const/let/function sharing and native-submit the launch form."""
    assert "/static/js/dashboard.js" in main.INDEX_HTML
    assert "/static/js/app_01.js" not in main.INDEX_HTML
    assert main.DASHBOARD_JS == extract_dashboard_script()
    assert "launchForm.addEventListener" in main.DASHBOARD_JS
    assert "function initHowtoView" in main.DASHBOARD_JS


def test_get_root_with_launch_query_serves_dashboard():
    """Start Recon without JS becomes GET /?domain=&wordlist=&interval=; still serve the UI."""
    handler = Mock(spec=main.CommandCenterHandler)
    handler.path = (
        "/?domain=home.lab"
        "&wordlist=%2Fapp%2Frecon_data%2Fwordlists%2Fsubdomains-top1million-110000.txt"
        "&interval="
    )
    handler.headers = {}
    handler._send_bytes = Mock()
    handler._send_json = Mock()
    handler.send_error = Mock()
    handler._require_auth = Mock(return_value={"username": "admin", "is_admin": True})
    main.CommandCenterHandler.do_GET(handler)
    handler.send_error.assert_not_called()
    handler._send_bytes.assert_called_once()
    html = handler._send_bytes.call_args[0][0].decode("utf-8")
    assert "/static/js/dashboard.js" in html


def test_serve_dashboard_js_bundle():
    handler = Mock()
    handler.path = "/static/js/dashboard.js?v=1"
    handler._send_bytes = Mock()
    assert main.serve_static_asset(handler) is True
    payload = handler._send_bytes.call_args[0][0]
    assert b"launchForm.addEventListener" in payload
    assert b"/api/run" in payload
