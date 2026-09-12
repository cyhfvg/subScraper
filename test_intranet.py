"""内网资产发现模块测试: 目标解析 / nmap XML / vhost JSON."""
from __future__ import annotations

import pytest
from pathlib import Path


from subscraper.discovery.ports import (
    DEFAULT_PORT_SPEC,
    build_nmap_command,
    parse_nmap_xml,
    web_endpoints_from_hosts,
)
from subscraper.discovery.vhost import (
    build_ffuf_vhost_command,
    parse_ffuf_vhost_json,
    vhost_host_pattern,
)
from subscraper.targets import TargetKind, parse_scan_target, parse_scan_targets, target_file_id


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.8" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web.corp.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

FFUF_JSON = """
{
  "results": [
    {"host": "intranet.corp.local", "url": "http://10.0.0.8/", "status": 200, "length": 1200,
     "input": {"FUZZ": "intranet"}},
    {"host": "intranet.corp.local", "url": "http://10.0.0.8/login", "status": 302, "length": 40,
     "input": {"FUZZ": "intranet"}},
    {"input": {"FUZZ": "vpn"}, "status": 401, "length": 80, "url": "http://10.0.0.8/"}
  ]
}
"""


class TestParseScanTarget:
    def test_domain(self):
        t = parse_scan_target("CORP.LOCAL")
        assert t is not None
        assert t.kind == TargetKind.DOMAIN
        assert t.normalized == "corp.local"
        assert t.needs_dns_enum is True

    def test_ipv4_and_url(self):
        t = parse_scan_target("https://10.0.0.8:8443/admin")
        assert t is not None
        assert t.kind == TargetKind.IPV4
        assert t.normalized == "10.0.0.8"
        assert t.is_network is True
        assert t.needs_dns_enum is False

    def test_cidr_not_stripped(self):
        t = parse_scan_target("10.1.0.0/24")
        assert t is not None
        assert t.kind == TargetKind.CIDR
        assert t.normalized == "10.1.0.0/24"
        assert target_file_id(t.normalized) == "10.1.0.0_24"

    def test_ipv6(self):
        t = parse_scan_target("2001:db8::1")
        assert t is not None
        assert t.kind == TargetKind.IPV6
        assert ":" not in t.file_id

    def test_single_label_intranet_name(self):
        t = parse_scan_target("dc01")
        assert t is not None
        assert t.kind == TargetKind.DOMAIN

    def test_reject_empty(self):
        assert parse_scan_target("   ") is None
        assert parse_scan_target("") is None

    def test_dedup(self):
        items = parse_scan_targets(["10.0.0.1", "10.0.0.1/", "corp.local"])
        assert [i.normalized for i in items] == ["10.0.0.1", "corp.local"]


class TestNmapHelpers:
    def test_build_command_default_ports(self):
        cmd = build_nmap_command("nmap", ["10.0.0.0/24"], "/tmp/x.xml")
        assert cmd[:6] == ["nmap", "-sV", "-Pn", "-T4", "--open", "-oX"]
        assert "-p" in cmd
        assert DEFAULT_PORT_SPEC in cmd
        assert cmd[-1] == "10.0.0.0/24"

    def test_build_command_top_ports(self):
        cmd = build_nmap_command("nmap", ["10.0.0.1"], "/tmp/x.xml", ports="top-100")
        assert "--top-ports" in cmd
        assert "100" in cmd
        assert "-p" not in cmd

    def test_build_command_rejects_empty(self):
        with pytest.raises(ValueError):
            build_nmap_command("nmap", [], "/tmp/x.xml")

    def test_parse_xml_open_web_ports(self):
        hosts = parse_nmap_xml(NMAP_XML)
        assert len(hosts) == 1
        host = hosts[0]
        assert host.ip == "10.0.0.8"
        assert "web.corp.local" in host.hostnames
        ports = {p.port for p in host.ports}
        assert ports == {22, 80, 8080}
        web = {p.port for p in host.web_ports()}
        assert web == {80, 8080}

    def test_parse_xml_garbage(self):
        assert parse_nmap_xml("not xml") == []
        assert parse_nmap_xml("") == []

    def test_web_endpoints(self):
        endpoints = web_endpoints_from_hosts(parse_nmap_xml(NMAP_XML))
        urls = {e["url"] for e in endpoints}
        assert "http://10.0.0.8" in urls
        assert "http://10.0.0.8:8080" in urls
        assert "http://web.corp.local" in urls


class TestVhostHelpers:
    def test_host_pattern(self):
        assert vhost_host_pattern("corp.local") == "FUZZ.corp.local"
        assert vhost_host_pattern(None) == "FUZZ"
        assert vhost_host_pattern("") == "FUZZ"

    def test_build_command(self):
        cmd = build_ffuf_vhost_command(
            "ffuf", "http://10.0.0.8/", "hosts.txt", "out.json", host_pattern="FUZZ.corp.local"
        )
        assert "Host: FUZZ.corp.local" in cmd
        assert "-ac" in cmd
        assert "-mc" in cmd

    def test_parse_json_dedup_and_fuzz_restore(self):
        hits = parse_ffuf_vhost_json(FFUF_JSON, "FUZZ.corp.local")
        hosts = [h.host for h in hits]
        assert hosts == ["intranet.corp.local", "vpn.corp.local"]
        assert hits[0].status == 200

    def test_parse_json_garbage(self):
        assert parse_ffuf_vhost_json("{") == []
        assert parse_ffuf_vhost_json("") == []


class TestIntranetPipelineConstants:
    """与 main 装配后的流水线常量对齐."""

    def test_pipeline_has_no_passive_steps(self):
        import main

        banned = {
            "subfinder",
            "assetfinder",
            "findomain",
            "sublist3r",
            "crtsh",
            "github-subdomains",
            "waybackurls",
            "gau",
        }
        assert banned.isdisjoint(set(main.PIPELINE_STEPS))
        assert banned.isdisjoint(set(main.TOOLS))
        for name in ("port_scan", "httpx", "vhost_enum", "screenshots", "nuclei", "nikto"):
            assert name in main.PIPELINE_STEPS

    def test_default_config_has_no_passive_toggles(self):
        import main

        cfg = main.default_config()
        for key in (
            "enable_subfinder",
            "enable_assetfinder",
            "enable_findomain",
            "enable_sublist3r",
            "enable_crtsh",
            "enable_github_subdomains",
            "enable_waybackurls",
            "enable_gau",
        ):
            assert key not in cfg
        assert cfg["enable_port_scan"] is True
        assert cfg["enable_vhost_enum"] is True
        assert "port_scan_ports" in cfg
        assert "enable_amass" not in cfg
        assert "amass_timeout" not in cfg
        assert "max_parallel_amass" not in cfg
        assert "amass" not in main.TOOLS
        assert "amass" not in main.PIPELINE_STEPS
        assert "amass" not in main.TOOL_GATES
        assert "dnsx" in main.PIPELINE_STEPS


class TestDnsxBrute:
    """dnsx 词表爆破替换 amass enum."""

    def test_builds_dnsx_wordlist_command(self, tmp_path, monkeypatch):
        import main

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("cloud\nwww\n", encoding="utf-8")
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "ensure_tool_installed", lambda name: True)
        monkeypatch.setattr(main, "apply_template_flags", lambda tool, cmd, ctx, cfg: cmd)
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text("cloud.home.lab\n", encoding="utf-8")
            return True

        monkeypatch.setattr(main, "run_subprocess", fake_run)
        path = main.dnsx_brute(
            "home.lab",
            config={"dns_resolvers": [], "tool_flag_templates": {}},
            wordlist=str(wordlist),
        )
        assert path is not None
        cmd = captured["cmd"]
        assert cmd[0] == main.TOOLS["dnsx"]
        assert "-silent" in cmd
        assert cmd[cmd.index("-d") + 1] == "home.lab"
        assert cmd[cmd.index("-w") + 1] == str(wordlist)
        assert "amass" not in cmd
        assert main.read_lines_file(path) == ["cloud.home.lab"]

    def test_resolver_file_uses_dash_r(self, tmp_path, monkeypatch):
        import main

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("cloud\n", encoding="utf-8")
        resolvers = tmp_path / "resolvers.txt"
        captured = {}

        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "ensure_tool_installed", lambda name: True)
        monkeypatch.setattr(main, "apply_template_flags", lambda tool, cmd, ctx, cfg: cmd)
        monkeypatch.setattr(main, "write_resolvers_file", lambda _r: resolvers)

        def fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text("cloud.home.lab\n", encoding="utf-8")
            return True

        monkeypatch.setattr(main, "run_subprocess", fake_run)
        main.dnsx_brute(
            "home.lab",
            config={"dns_resolvers": ["10.10.1.1"], "tool_flag_templates": {}},
            wordlist=str(wordlist),
        )
        cmd = captured["cmd"]
        assert "-rL" not in cmd
        assert cmd[cmd.index("-r") + 1] == str(resolvers)


    def test_missing_wordlist_returns_empty(self, monkeypatch):
        import main

        monkeypatch.setattr(main, "ensure_tool_installed", lambda name: True)
        result = main.dnsx_collect_subdomains(
            "home.lab",
            config={"default_wordlist": "", "dns_resolvers": [], "tool_flag_templates": {}},
            wordlist=None,
        )
        assert result == []

    def test_legacy_amass_done_migrates(self):
        import main

        state = {"targets": {}}
        tgt = main.ensure_target_state(state, "home.lab")
        tgt["flags"]["amass_done"] = True
        tgt["flags"]["dns_brute_done"] = False
        migrated = main.ensure_target_state(state, "home.lab")
        assert migrated["flags"].get("dns_brute_done") is True
        assert "amass_done" not in migrated["flags"]

