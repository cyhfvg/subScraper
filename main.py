#!/usr/bin/env python3
"""Recon Command Center.

长期维护入口: 实现拆在 subscraper/fragments 与 web/ 中, 加载进本模块命名空间,
以便现有测试对 main.DATA_DIR / main.RUNNING_JOBS 的重绑定继续生效.
"""
from __future__ import annotations

import logging
import mimetypes
import os
import time
from http import HTTPStatus
from pathlib import Path
from urllib.parse import unquote, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent
WEB_ROOT = PROJECT_ROOT / "web"
FRAGMENT_DIR = PROJECT_ROOT / "subscraper" / "fragments"


def _configure_logging() -> None:
    """初始化 UTC 日志格式.

    Returns:
        None.
    Raises:
        无.
    Example:
        _configure_logging()
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.Formatter.converter = time.gmtime



_configure_logging()


def load_login_html() -> str:
    """读取登录页模板.

    Returns:
        登录页 HTML.
    Raises:
        FileNotFoundError: 模板缺失.
    Example:
        html = load_login_html()
    """
    return (WEB_ROOT / "templates" / "login.html").read_text(encoding="utf-8")


def load_index_html() -> str:
    """组装仪表盘 HTML.

    Returns:
        完整 index HTML.
    Raises:
        FileNotFoundError: 模板或 partial 缺失.
    Example:
        page = load_index_html()
    """
    prefix = (WEB_ROOT / "templates" / "prefix.html").read_text(encoding="utf-8")
    suffix = (WEB_ROOT / "templates" / "suffix.html").read_text(encoding="utf-8")
    manifest = (WEB_ROOT / "templates" / "partials" / "manifest.txt").read_text(encoding="utf-8")
    parts = [prefix]
    for name in manifest.splitlines():
        name = name.strip()
        if not name:
            continue
        parts.append((WEB_ROOT / "templates" / "partials" / f"{name}.html").read_text(encoding="utf-8"))
    parts.append(suffix)
    return "\n".join(parts)


def load_dashboard_js() -> str:
    """按 manifest 拼接仪表盘 JS, 保持单脚本作用域.

    拆文件后的 const/let 与 function 声明不能跨 <script> 共享.
    浏览器必须只加载这一份拼接结果, 否则 Launch Scan 会退化成 GET /?domain= 并 404.

    Returns:
        拼接后的 JavaScript 文本.
    Raises:
        FileNotFoundError: manifest 或脚本缺失.
    Example:
        js = load_dashboard_js()
    """
    js_dir = WEB_ROOT / "static" / "js"
    manifest = (js_dir / "manifest.txt").read_text(encoding="utf-8")
    parts: list[str] = []
    for name in manifest.splitlines():
        name = name.strip()
        if not name or name.startswith("#"):
            continue
        parts.append((js_dir / name).read_text(encoding="utf-8"))
    if not parts:
        raise FileNotFoundError("dashboard JS manifest is empty")
    return "\n".join(parts)


def serve_static_asset(handler) -> bool:
    """安全地从 web/static 提供静态文件.

    Args:
        handler: BaseHTTPRequestHandler 实例.
    Returns:
        True 表示已写入响应, False 表示文件不存在或路径非法.
    Raises:
        无. 路径错误返回 False.
    Example:
        if serve_static_asset(self):
            return
    """
    route = urlparse(handler.path).path
    rel = unquote(route[len("/static/") :]).lstrip("/")
    if not rel or ".." in rel.split("/"):
        return False
    if rel == "js/dashboard.js":
        data = DASHBOARD_JS.encode("utf-8")
        handler._send_bytes(
            data,
            status=HTTPStatus.OK,
            content_type="application/javascript; charset=utf-8",
        )
        return True
    requested = (WEB_ROOT / "static" / rel).resolve()
    base = (WEB_ROOT / "static").resolve()
    try:
        if not str(requested).startswith(str(base) + os.sep):
            return False
    except Exception:
        return False
    if not requested.is_file():
        return False
    mime, _ = mimetypes.guess_type(str(requested))
    data = requested.read_bytes()
    handler._send_bytes(data, status=HTTPStatus.OK, content_type=mime or "application/octet-stream")
    return True


def _load_fragments() -> None:
    """按清单把实现片段 exec 进本模块.

    Returns:
        None.
    Raises:
        FileNotFoundError: 清单或片段缺失.
        SyntaxError: 片段无法编译.
    Example:
        _load_fragments()
    """
    manifest = (FRAGMENT_DIR / "manifest.txt").read_text(encoding="utf-8")
    ns = globals()
    for name in manifest.splitlines():
        name = name.strip()
        if not name or name.startswith("#"):
            continue
        path = FRAGMENT_DIR / name
        code = path.read_text(encoding="utf-8")
        exec(compile(code, str(path), "exec"), ns)


_load_fragments()

BUNDLED_NUCLEI_TEMPLATES_DIR = PROJECT_ROOT / "nuclei-templates"
INDEX_HTML = load_index_html()
DASHBOARD_JS = load_dashboard_js()


if __name__ == "__main__":
    globals()["main"]()
