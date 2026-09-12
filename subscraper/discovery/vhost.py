"""HTTP Host 头 vhost 枚举的命令构造与结果解析.

内网常见场景: 同一 IP:端口上挂多个内部站点. 不访问互联网.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,500"


@dataclass(frozen=True)
class VhostHit:
    """一次 vhost 命中."""

    host: str
    url: str
    status: int
    length: int = 0


def vhost_host_pattern(base_domain: Optional[str]) -> str:
    """构造 ffuf Host 头 FUZZ 模板.

    Args:
        base_domain: 域名目标时传入, 例如 corp.local; IP 扫描时传 None.

    Returns:
        str: `FUZZ.corp.local` 或 `FUZZ`.

    Raises:
        无.

    调用示例:
        vhost_host_pattern("corp.local")  # "FUZZ.corp.local"
        vhost_host_pattern(None)          # "FUZZ"
    """
    domain = (base_domain or "").strip().lower().strip(".")
    if not domain:
        return "FUZZ"
    return f"FUZZ.{domain}"


def build_ffuf_vhost_command(
    ffuf_bin: str,
    target_url: str,
    wordlist: str,
    output_json: str,
    host_pattern: str = "FUZZ",
    match_codes: str = DEFAULT_MATCH_CODES,
    extra_args: Optional[Sequence[str]] = None,
) -> List[str]:
    """构造 ffuf vhost 爆破命令.

    Args:
        ffuf_bin: ffuf 可执行文件.
        target_url: 形如 http://10.0.0.8:8080/.
        wordlist: Host 名字典.
        output_json: -o JSON 路径.
        host_pattern: Host 头, 含 FUZZ.
        match_codes: -mc 状态码列表.
        extra_args: 额外 flags.

    Returns:
        List[str]: argv.

    Raises:
        ValueError: 必填参数为空.

    调用示例:
        build_ffuf_vhost_command("ffuf", "http://10.0.0.8/", "hosts.txt", "out.json")
    """
    if not ffuf_bin or not str(ffuf_bin).strip():
        raise ValueError("ffuf_bin is required")
    if not target_url or not str(target_url).strip():
        raise ValueError("target_url is required")
    if not wordlist or not str(wordlist).strip():
        raise ValueError("wordlist is required")
    if not output_json or not str(output_json).strip():
        raise ValueError("output_json is required")
    cmd: List[str] = [
        str(ffuf_bin),
        "-u",
        str(target_url),
        "-H",
        f"Host: {host_pattern}",
        "-w",
        str(wordlist),
        "-of",
        "json",
        "-o",
        str(output_json),
        "-mc",
        match_codes or DEFAULT_MATCH_CODES,
        "-ac",
    ]
    if extra_args:
        cmd.extend(str(a) for a in extra_args if str(a))
    return cmd


def _host_from_result(raw: Dict[str, Any], fallback_pattern: str) -> str:
    """从 ffuf result 对象取出主机名."""
    host = (raw.get("host") or "").strip()
    if host:
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        return host.lower()
    input_obj = raw.get("input") or {}
    fuzz = ""
    if isinstance(input_obj, dict):
        fuzz = str(input_obj.get("FUZZ") or input_obj.get("HOST") or "").strip()
    if fuzz and "FUZZ" in (fallback_pattern or ""):
        return fallback_pattern.replace("FUZZ", fuzz).lower()
    if fuzz:
        return fuzz.lower()
    url = (raw.get("url") or "").strip()
    if url:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        if parsed.hostname:
            return parsed.hostname.lower()
    return ""


def parse_ffuf_vhost_json(text: str, host_pattern: str = "FUZZ") -> List[VhostHit]:
    """解析 ffuf JSON 输出为 vhost 命中.

    Args:
        text: ffuf -of json 文件内容.
        host_pattern: 当时使用的 Host 模板, 用于从 FUZZ 还原 FQDN.

    Returns:
        List[VhostHit]: 解析失败返回空列表.

    Raises:
        无.

    调用示例:
        parse_ffuf_vhost_json(Path("ffuf.json").read_text(), "FUZZ.corp.local")
    """
    payload = (text or "").strip()
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        logger.warning("ffuf JSON parse failed: %s", exc)
        return []
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []
    hits: List[VhostHit] = []
    seen = set()
    for raw in results:
        if not isinstance(raw, dict):
            continue
        host = _host_from_result(raw, host_pattern)
        if not host or host in seen:
            continue
        try:
            status = int(raw.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        try:
            length = int(raw.get("length") or 0)
        except (TypeError, ValueError):
            length = 0
        url = (raw.get("url") or "").strip()
        seen.add(host)
        hits.append(VhostHit(host=host, url=url, status=status, length=length))
    return hits
