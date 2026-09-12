"""内网主动资产发现: 端口扫描与 vhost 枚举."""

from subscraper.discovery.ports import (
    DEFAULT_PORT_SPEC,
    WEB_PORTS,
    HostPorts,
    OpenPort,
    build_nmap_command,
    parse_nmap_xml,
    web_endpoints_from_hosts,
)
from subscraper.discovery.vhost import (
    VhostHit,
    build_ffuf_vhost_command,
    parse_ffuf_vhost_json,
    vhost_host_pattern,
)

__all__ = [
    "DEFAULT_PORT_SPEC",
    "WEB_PORTS",
    "HostPorts",
    "OpenPort",
    "VhostHit",
    "build_ffuf_vhost_command",
    "build_nmap_command",
    "parse_ffuf_vhost_json",
    "parse_nmap_xml",
    "vhost_host_pattern",
    "web_endpoints_from_hosts",
]
