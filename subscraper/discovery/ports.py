"""nmap 端口扫描命令构造与 XML 解析.

纯函数, 不启动子进程, 便于单测. 不访问互联网.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# 内网常见服务端口. 可通过 config.port_scan_ports 覆盖.
DEFAULT_PORT_SPEC = (
    "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,993,995,"
    "1433,1521,2049,2181,3306,3389,5432,5601,5672,5900,5985,6379,7001,8000,8080,"
    "8081,8443,8888,9000,9090,9200,9300,11211,27017"
)

# 视为 Web 入口、后续做 httpx / vhost / 截图 / 漏扫的端口.
WEB_PORTS = frozenset(
    {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443, 10443, 10443}
)

_WEB_SERVICE_NAMES = frozenset(
    {
        "http",
        "https",
        "http-proxy",
        "https-alt",
        "ssl/http",
        "http-alt",
        "http-api",
        "sun-answerbook",
        "opsmessaging",
    }
)


@dataclass
class OpenPort:
    """单主机上的一个开放端口."""

    port: int
    protocol: str
    service: str = ""
    product: str = ""
    version: str = ""
    state: str = "open"

    def is_web(self) -> bool:
        """是否按 Web 服务处理.

        Returns:
            bool: 端口号或服务名命中 Web 规则.

        Raises:
            无.
        """
        if self.port in WEB_PORTS:
            return True
        name = (self.service or "").lower()
        if name in _WEB_SERVICE_NAMES:
            return True
        if name.startswith("ssl/") and "http" in name:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可写入 SQLite/state 的字典.

        Returns:
            Dict[str, Any].
        """
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "state": self.state,
            "web": self.is_web(),
        }


@dataclass
class HostPorts:
    """一台存活主机及其开放端口."""

    ip: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[OpenPort] = field(default_factory=list)
    status: str = "up"

    def web_ports(self) -> List[OpenPort]:
        """返回判定为 Web 的端口.

        Returns:
            List[OpenPort].
        """
        return [p for p in self.ports if p.is_web()]

    def identities(self) -> List[str]:
        """用于写入资产表的主机标识: IP + PTR/反向名.

        Returns:
            List[str]: 去重后的标识.
        """
        names: List[str] = []
        seen = set()
        for item in [self.ip, *self.hostnames]:
            key = (item or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            names.append(key)
        return names


def build_nmap_command(
    nmap_bin: str,
    targets: Sequence[str],
    output_xml: str,
    ports: str = DEFAULT_PORT_SPEC,
    extra_args: Optional[Sequence[str]] = None,
) -> List[str]:
    """构造 nmap 服务探测命令.

    Args:
        nmap_bin: nmap 可执行文件路径.
        targets: IP / CIDR / 主机名列表.
        output_xml: -oX 输出路径.
        ports: 端口规格. 空字符串使用 nmap 默认; `top-N` 使用 --top-ports N.
        extra_args: 额外参数, 例如模板 flags.

    Returns:
        List[str]: 完整 argv.

    Raises:
        ValueError: nmap_bin 为空或 targets 为空.

    调用示例:
        build_nmap_command("nmap", ["10.0.0.0/24"], "/tmp/scan.xml")
    """
    if not nmap_bin or not str(nmap_bin).strip():
        raise ValueError("nmap_bin is required")
    cleaned = [str(t).strip() for t in targets if str(t).strip()]
    if not cleaned:
        raise ValueError("targets must not be empty")
    cmd: List[str] = [
        str(nmap_bin),
        "-sV",
        "-Pn",
        "-T4",
        "--open",
        "-oX",
        str(output_xml),
    ]
    spec = (ports or "").strip()
    if spec:
        if spec.lower().startswith("top-"):
            number = spec.split("-", 1)[1].strip()
            if not number.isdigit():
                raise ValueError(f"invalid top-ports spec: {ports}")
            cmd.extend(["--top-ports", number])
        else:
            cmd.extend(["-p", spec])
    if extra_args:
        cmd.extend(str(a) for a in extra_args if str(a))
    cmd.extend(cleaned)
    return cmd


def parse_nmap_xml(xml_text: str) -> List[HostPorts]:
    """解析 nmap -oX 输出.

    Args:
        xml_text: XML 全文.

    Returns:
        List[HostPorts]: 状态为 up 且至少有一个 open 端口的主机.
            XML 为空或损坏时返回空列表并记日志.

    Raises:
        无. 解析失败返回 [].

    调用示例:
        parse_nmap_xml(Path("scan.xml").read_text())
    """
    text = (xml_text or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        logger.warning("nmap XML parse failed: %s", exc)
        return []
    hosts: List[HostPorts] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = (status_el.get("state") if status_el is not None else "") or ""
        if status and status != "up":
            continue
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in {"ipv4", "ipv6"}:
                ip = (addr.get("addr") or "").strip()
                if ip:
                    break
        if not ip:
            continue
        hostnames: List[str] = []
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = (hn.get("name") or "").strip().lower()
                if name:
                    hostnames.append(name)
        ports: List[OpenPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = (state_el.get("state") if state_el is not None else "") or ""
                if state != "open":
                    continue
                try:
                    port_id = int(port_el.get("portid") or "0")
                except ValueError:
                    continue
                if port_id <= 0:
                    continue
                service_el = port_el.find("service")
                service = ""
                product = ""
                version = ""
                if service_el is not None:
                    service = (service_el.get("name") or "").strip()
                    product = (service_el.get("product") or "").strip()
                    version = (service_el.get("version") or "").strip()
                ports.append(
                    OpenPort(
                        port=port_id,
                        protocol=(port_el.get("protocol") or "tcp").strip() or "tcp",
                        service=service,
                        product=product,
                        version=version,
                        state=state,
                    )
                )
        if not ports:
            continue
        hosts.append(HostPorts(ip=ip, hostnames=hostnames, ports=ports, status=status or "up"))
    return hosts


def web_endpoints_from_hosts(hosts: Iterable[HostPorts]) -> List[Dict[str, str]]:
    """从端口结果生成 http/https URL.

    Args:
        hosts: parse_nmap_xml 的结果.

    Returns:
        List[Dict[str, str]]: 每项含 host, ip, port, url.

    Raises:
        无.

    调用示例:
        web_endpoints_from_hosts(parse_nmap_xml(xml))
    """
    endpoints: List[Dict[str, str]] = []
    seen = set()
    for host in hosts:
        for port in host.web_ports():
            scheme = "https" if port.port in {443, 8443, 9443, 10443} or "ssl" in (port.service or "").lower() or port.service == "https" else "http"
            if port.port in {80, 443}:
                url = f"{scheme}://{host.ip}"
            else:
                url = f"{scheme}://{host.ip}:{port.port}"
            key = (host.ip, port.port, scheme)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(
                {
                    "host": host.ip,
                    "ip": host.ip,
                    "port": str(port.port),
                    "url": url,
                    "service": port.service,
                }
            )
            for name in host.hostnames:
                if port.port in {80, 443}:
                    named_url = f"{scheme}://{name}"
                else:
                    named_url = f"{scheme}://{name}:{port.port}"
                nkey = (name, port.port, scheme)
                if nkey in seen:
                    continue
                seen.add(nkey)
                endpoints.append(
                    {
                        "host": name,
                        "ip": host.ip,
                        "port": str(port.port),
                        "url": named_url,
                        "service": port.service,
                    }
                )
    return endpoints
