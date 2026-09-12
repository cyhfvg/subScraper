"""内网扫描目标解析: 域名 / IPv4 / IPv6 / CIDR.

纯内网资产发现入口. 不访问互联网 API, 只做本地字符串分类与规范化.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional


class TargetKind(str, Enum):
    """扫描目标类型."""

    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"


@dataclass(frozen=True)
class ScanTarget:
    """规范化后的扫描目标.

    Attributes:
        raw: 用户原始输入 (去空白).
        normalized: 用于 job key / 状态存储的小写形式.
        kind: 目标类型.
        file_id: 可安全用于文件名的标识 (CIDR 的 / 换成 _).
    """

    raw: str
    normalized: str
    kind: TargetKind
    file_id: str

    @property
    def is_network(self) -> bool:
        """是否为 IP 或网段, 应跳过 DNS 爆破.

        Returns:
            bool: IP/CIDR 为 True.

        Raises:
            无.

        调用示例:
            ScanTarget("10.0.0.1", "10.0.0.1", TargetKind.IPV4, "10.0.0.1").is_network
        """
        return self.kind in (TargetKind.IPV4, TargetKind.IPV6, TargetKind.CIDR)

    @property
    def needs_dns_enum(self) -> bool:
        """是否需要对域名做主动 DNS 爆破.

        Returns:
            bool: 仅 DOMAIN 为 True.

        Raises:
            无.
        """
        return self.kind == TargetKind.DOMAIN


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9*](?:[A-Za-z0-9*-]{0,61}[A-Za-z0-9*])?"
    r"(?:\.(?!-)[A-Za-z0-9*](?:[A-Za-z0-9*-]{0,61}[A-Za-z0-9*])?)+$"
)
_WILDCARD_PREFIX = "*."


def target_file_id(value: str) -> str:
    """把目标字符串变成文件系统安全标识.

    Args:
        value: 规范化后的目标, 例如 10.0.0.0/24 或 2001:db8::1.

    Returns:
        str: 不含路径分隔符的标识.

    Raises:
        无.

    调用示例:
        target_file_id("10.0.0.0/24")  # "10.0.0.0_24"
    """
    text = (value or "").strip().lower()
    text = text.replace("/", "_").replace(":", "_").replace("%", "_")
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    return text.strip("._") or "target"


def _strip_url_noise(value: str) -> str:
    """去掉 scheme / 用户信息 / 端口 / 路径, 保留 CIDR 前缀长度.

    Args:
        value: 原始输入.

    Returns:
        str: 清洗后的小写字符串.

    Raises:
        无.
    """
    cleaned = (value or "").strip()
    if not cleaned:
        return ""
    cleaned = _SCHEME_RE.sub("", cleaned)
    if "@" in cleaned:
        cleaned = cleaned.rsplit("@", 1)[-1]
    # IPv6 URL: [2001:db8::1]:8443 或 [2001:db8::1]
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end > 0:
            host = cleaned[1:end]
            rest = cleaned[end + 1 :]
            if rest.startswith(":"):
                return host.lower()
            return (host + rest).lower()
    # 保留 IPv4 CIDR 的 /
    cidr_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})(?:[:/?#].*)?$", cleaned)
    if cidr_match:
        return cidr_match.group(1).lower()
    for delimiter in ("?", "#"):
        if delimiter in cleaned:
            cleaned = cleaned.split(delimiter, 1)[0]
    if cleaned.count(":") == 1:
        host, maybe_port = cleaned.rsplit(":", 1)
        port_token = maybe_port.split("/", 1)[0]
        if port_token.isdigit():
            cleaned = host
    if "/" in cleaned and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d", cleaned):
        cleaned = cleaned.split("/", 1)[0]
    cleaned = cleaned.strip().strip(".")
    return cleaned.lower()


def parse_scan_target(value: str) -> Optional[ScanTarget]:
    """解析单个扫描目标.

    Args:
        value: 域名, IPv4, IPv6, CIDR, 或带 scheme 的 URL.

    Returns:
        Optional[ScanTarget]: 无法识别时返回 None.

    Raises:
        无. 非法地址被当作失败而非异常.

    调用示例:
        parse_scan_target("https://10.0.0.8:8443/")
        parse_scan_target("10.1.0.0/24")
        parse_scan_target("corp.local")
    """
    raw = (value or "").strip()
    if not raw:
        return None
    cleaned = _strip_url_noise(raw)
    if not cleaned:
        return None
    wildcard = False
    if cleaned.startswith(_WILDCARD_PREFIX):
        wildcard = True
        cleaned = cleaned[2:]
    if cleaned.endswith(".*"):
        # TLD 通配交给 expand_wildcard_targets, 这里仍记为 domain.
        kind = TargetKind.DOMAIN
        normalized = cleaned.lower()
        if wildcard:
            normalized = cleaned  # expand 阶段再处理 *.
        return ScanTarget(raw=raw, normalized=normalized, kind=kind, file_id=target_file_id(normalized))
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
        if network.prefixlen == network.max_prefixlen:
            kind = TargetKind.IPV4 if network.version == 4 else TargetKind.IPV6
            normalized = str(network.network_address)
        else:
            kind = TargetKind.CIDR
            normalized = str(network)
        return ScanTarget(
            raw=raw,
            normalized=normalized,
            kind=kind,
            file_id=target_file_id(normalized),
        )
    except ValueError:
        pass
    try:
        addr = ipaddress.ip_address(cleaned)
        kind = TargetKind.IPV4 if addr.version == 4 else TargetKind.IPV6
        normalized = str(addr)
        return ScanTarget(
            raw=raw,
            normalized=normalized,
            kind=kind,
            file_id=target_file_id(normalized),
        )
    except ValueError:
        pass
    candidate = cleaned.rstrip(".")
    if not candidate or candidate in {".", "*"}:
        return None
    if not _DOMAIN_RE.match(candidate) and not candidate.endswith(".*"):
        # 允许单标签内网名, 如 dc01
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", candidate):
            return None
    normalized = candidate.lower()
    return ScanTarget(
        raw=raw,
        normalized=normalized,
        kind=TargetKind.DOMAIN,
        file_id=target_file_id(normalized),
    )


def parse_scan_targets(values: Iterable[str]) -> List[ScanTarget]:
    """解析一组目标, 按 normalized 去重并保持顺序.

    Args:
        values: 原始输入可迭代对象.

    Returns:
        List[ScanTarget]: 有效目标列表.

    Raises:
        无.

    调用示例:
        parse_scan_targets(["corp.local", "10.0.0.1", "10.0.0.1"])
    """
    seen = set()
    result: List[ScanTarget] = []
    for item in values:
        parsed = parse_scan_target(item)
        if parsed is None:
            continue
        if parsed.normalized in seen:
            continue
        seen.add(parsed.normalized)
        result.append(parsed)
    return result


def is_ip_or_cidr(value: str) -> bool:
    """判断字符串是否为 IP 或 CIDR.

    Args:
        value: 待检测字符串.

    Returns:
        bool.

    Raises:
        无.
    """
    parsed = parse_scan_target(value)
    return bool(parsed and parsed.is_network)
