#!/usr/bin/env python3
"""Extract dashboard assets and slice main.py into loadable fragments."""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = (ROOT / "main.py").read_text(encoding="utf-8")
WEB = ROOT / "web"
FRAG = ROOT / "subscraper" / "fragments"
MAX_LINES = 470


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content += "\n"
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({content.count(chr(10))} lines)")


def extract_index_html(src: str) -> tuple[str, str]:
    marker = "INDEX_HTML = \"\"\""
    start = src.find(marker)
    if start < 0:
        raise SystemExit("INDEX_HTML not found")
    content_start = start + len(marker)
    end = src.find('\n"""\n', content_start)
    if end < 0:
        raise SystemExit("INDEX_HTML closer not found")
    html = src[content_start:end]
    new_src = src[:start] + src[end + len('\n"""\n') :]
    return html, new_src


def pack_lines(lines: list[str], boundary) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if current and len(current) >= MAX_LINES - 25 and boundary(line):
            chunks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append(current)
    return chunks


def split_css(css: str) -> list[str]:
    def boundary(line: str) -> bool:
        s = line.lstrip()
        return s.startswith(".") or s.startswith("@media") or s.startswith(":")

    names = []
    for i, chunk in enumerate(pack_lines(css.splitlines(keepends=True), boundary), start=1):
        name = f"theme_{i:02d}.css"
        write_text(WEB / "static" / "css" / name, "".join(chunk))
        names.append(name)
    return names


def split_js(js: str) -> list[str]:
    def boundary(line: str) -> bool:
        return bool(re.match(r"^(function |async function |// ----)", line))

    names = []
    for i, chunk in enumerate(pack_lines(js.splitlines(keepends=True), boundary), start=1):
        name = f"app_{i:02d}.js"
        write_text(WEB / "static" / "js" / name, "".join(chunk))
        names.append(name)
    write_text(WEB / "static" / "js" / "manifest.txt", "\n".join(names) + "\n")
    return names


def split_html_template(html: str, css_files: list[str], js_files: list[str]) -> None:
    style_m = re.search(r"<style>.*?</style>\n?", html, re.S)
    script_ms = list(re.finditer(r"<script>.*?</script>\n?", html, re.S))
    if not style_m or not script_ms:
        raise SystemExit("style/script missing")
    script_m = script_ms[-1]
    without_assets = (
        html[: style_m.start()]
        + "<!--HEAD_ASSETS-->\n"
        + html[style_m.end() : script_m.start()]
        + "<!--BODY_SCRIPTS-->\n"
        + html[script_m.end() :]
    )

    parts = re.split(r'(?=<section class="module")', without_assets)
    prefix = parts[0]
    section_names: list[str] = []
    suffix_parts: list[str] = []
    for chunk in parts[1:]:
        m = re.match(r"(<section class=\"module\".*?</section>\s*)(.*)$", chunk, re.S)
        if not m:
            suffix_parts.append(chunk)
            continue
        section, rest = m.group(1), m.group(2)
        view = re.search(r'data-view="([^"]+)"', section)
        name = view.group(1) if view else f"section{len(section_names)}"
        write_text(WEB / "templates" / "partials" / f"{name}.html", section.strip() + "\n")
        section_names.append(name)
        if rest.strip():
            suffix_parts.append(rest)

    head_assets = "\n".join(f'  <link rel="stylesheet" href="/static/css/{n}">' for n in css_files)
    head_assets += '\n  <link rel="stylesheet" href="/static/css/jobs.css">\n'
    body_scripts = '  <script src="/static/js/dashboard.js"></script>'
    prefix = prefix.replace("<!--HEAD_ASSETS-->", head_assets)
    suffix = "".join(suffix_parts).replace("<!--BODY_SCRIPTS-->", body_scripts + "\n")
    write_text(WEB / "templates" / "prefix.html", prefix)
    write_text(WEB / "templates" / "suffix.html", suffix)
    write_text(WEB / "templates" / "partials" / "manifest.txt", "\n".join(section_names) + "\n")


def slice_python(src: str) -> None:
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    nodes = list(tree.body)
    start_idx = 0
    if nodes and isinstance(nodes[0], ast.Expr) and isinstance(getattr(nodes[0], "value", None), ast.Constant):
        start_idx = 1

    items: list[tuple[str, int, int]] = []
    for node in nodes[start_idx:]:
        a = node.lineno
        b = int(getattr(node, "end_lineno") or a)
        name = getattr(node, "name", type(node).__name__)
        items.append((str(name), a, b))

    first_code = items[0][1]
    header = "".join(lines[: first_code - 1])
    write_text(FRAG / "00_header.py", header)
    manifest = ["00_header.py"]

    packed: list[tuple[str, int, int]] = []
    cur_name, cur_a, cur_b = items[0]
    for name, a, b in items[1:]:
        # Keep huge classes whole; they are split manually later.
        if (b - cur_a + 1) > MAX_LINES and (cur_b - cur_a + 1) > 20:
            packed.append((cur_name, cur_a, cur_b))
            cur_name, cur_a, cur_b = name, a, b
        else:
            cur_b = b
    packed.append((cur_name, cur_a, cur_b))

    for i, (lead, a, b) in enumerate(packed, start=1):
        fname = f"{i:02d}_{_slug(lead)}.py"
        chunk = "".join(lines[a - 1 : b])
        if fname.endswith("main.py") or chunk.strip().endswith('main()'):
            chunk = re.sub(r'\n+if __name__ == "__main__":\n    main\(\)\s*$', "\n", chunk)
        banner = f'"""Fragment {fname}. Loaded into the main module namespace."""\n'
        write_text(FRAG / fname, banner + chunk)
        manifest.append(fname)
        nlines = (banner + chunk).count("\n") + 1
        if nlines > 600:
            print(f"WARNING oversize {fname}: {nlines}")
    write_text(FRAG / "manifest.txt", "\n".join(manifest) + "\n")


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_").lower()
    return (s or "chunk")[:40]


def main() -> None:
    html, src_wo_html = extract_index_html(SRC)
    style_m = re.search(r"<style>(.*?)</style>", html, re.S)
    script_ms = list(re.finditer(r"<script>(.*?)</script>", html, re.S))
    if not style_m or not script_ms:
        raise SystemExit("index assets missing")
    css_files = split_css(style_m.group(1).strip("\n"))
    js_files = split_js(script_ms[-1].group(1).strip("\n"))
    split_html_template(html, css_files, js_files)
    slice_python(src_wo_html)
    print("split complete")


if __name__ == "__main__":
    main()
