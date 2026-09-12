"""Fragment 14_findomain_enum.py. Loaded into the main module namespace."""
def _artifact_path(domain: str, prefix: str, suffix: str) -> Path:
    """按目标生成 recon_data 下的产物路径, CIDR 中的 / 会替换掉.

    Args:
        domain: 目标标识.
        prefix: 文件前缀, 如 nmap.
        suffix: 含点的后缀, 如 .xml.

    Returns:
        Path.

    Raises:
        无.
    """
    return DATA_DIR / f"{prefix}_{target_file_id(domain)}{suffix}"


def dnsx_verify(subdomains: List[str], domain: str, job_domain: Optional[str] = None,
                config: Optional[Dict[str, Any]] = None) -> List[str]:
    """用 dnsx 主动解析主机名, 只打内网/指定 resolver.

    Args:
        subdomains: 待验证主机.
        domain: 目标标识, 用于产物文件名.
        job_domain: 可选 job 日志.
        config: 含 dns_resolvers.

    Returns:
        List[str]: 解析成功的主机; 工具缺失时原样返回.

    Raises:
        无.
    """
    if not ensure_tool_installed("dnsx"):
        return subdomains
    if not subdomains:
        return []

    input_path = _artifact_path(domain, "dnsx_input", ".txt")
    out_path = _artifact_path(domain, "dnsx", ".txt")
    try:
        with open(input_path, "w", encoding="utf-8") as f:
            for sub in subdomains:
                f.write(sub + "\n")
    except OSError as exc:
        log(f"dnsx input write failed: {exc}")
        return subdomains

    cmd = [
        TOOLS["dnsx"],
        "-silent",
        "-l", str(input_path),
        "-o", str(out_path),
    ]
    cfg = config if config is not None else get_config()
    resolvers = _normalize_resolver_list(cfg.get("dns_resolvers"))
    if resolvers:
        rf = write_resolvers_file(resolvers)
        cmd.extend(["-r", str(rf)])
        if job_domain:
            job_log_append(job_domain, f"DNSx DNS resolvers: {', '.join(resolvers)}", "dnsx")
    context = {
        "DOMAIN": domain,
        "INPUT": str(input_path),
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("dnsx", cmd, context, cfg)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="dnsx")
    return read_lines_file(out_path) if success else subdomains



def dnsx_brute(
    domain: str,
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
    wordlist: Optional[str] = None,
) -> Optional[Path]:
    """用 dnsx 对根域名做词表爆破, 只留下能解析的 FQDN.

    Args:
        domain: 根域名.
        config: 运行配置, None 时读 get_config().
        job_domain: 可选, 写入 job log 并响应暂停点.
        wordlist: 子域名前缀字典; 为空则回退 config.default_wordlist.

    Returns:
        Optional[Path]: dnsx 文本输出路径; 未安装、无字典或执行失败时返回 None.

    Raises:
        无. 子进程异常由 run_subprocess 捕获.

    调用示例:
        dnsx_brute("home.lab", wordlist="/app/recon_data/wordlists/subs.txt")
    """
    if not ensure_tool_installed("dnsx"):
        return None

    cfg = config if config is not None else get_config()
    raw_wordlist = ""
    if wordlist and str(wordlist).strip():
        raw_wordlist = str(wordlist).strip()
    else:
        raw_wordlist = str(cfg.get("default_wordlist") or "").strip()
    resolved_wordlist = resolve_wordlist_path(raw_wordlist) if raw_wordlist else None
    if not resolved_wordlist or not Path(resolved_wordlist).is_file():
        log(f"dnsx brute wordlist not found, DNS brute-force skipped: {raw_wordlist or '(empty)'}")
        if job_domain:
            job_log_append(
                job_domain,
                f"dnsx brute wordlist not found: {raw_wordlist or '(empty)'}",
                "dnsx",
            )
        return None

    out_path = _artifact_path(domain, "dnsx_brute", ".txt")
    cmd = [
        TOOLS["dnsx"],
        "-silent",
        "-d", domain,
        "-w", resolved_wordlist,
        "-o", str(out_path),
    ]
    resolvers = _normalize_resolver_list(cfg.get("dns_resolvers"))
    if resolvers:
        rf = write_resolvers_file(resolvers)
        cmd.extend(["-r", str(rf)])
        if job_domain:
            job_log_append(job_domain, f"dnsx brute DNS resolvers: {', '.join(resolvers)}", "dnsx")
    log(f"dnsx DNS brute-force wordlist: {resolved_wordlist}")
    if job_domain:
        job_log_append(job_domain, f"dnsx DNS brute-force wordlist: {resolved_wordlist}", "dnsx")
    context = {
        "DOMAIN": domain,
        "WORDLIST": resolved_wordlist,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("dnsx", cmd, context, cfg)
    success = run_subprocess(cmd, job_domain=job_domain, step="dnsx")
    return out_path if success and out_path.exists() else None


def dnsx_collect_subdomains(
    domain: str,
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
    wordlist: Optional[str] = None,
) -> List[str]:
    """运行 dnsx 词表爆破并解析发现的子域名.

    Args:
        domain: 根域名.
        config: 运行配置.
        job_domain: 可选 job 标识.
        wordlist: 传给 dnsx_brute 的前缀字典.

    Returns:
        List[str]: 去重排序后的子域名; 失败时为空列表.

    Raises:
        无.

    调用示例:
        dnsx_collect_subdomains("home.lab", wordlist="/path/subs.txt")
    """
    out_path = dnsx_brute(domain, config=config, job_domain=job_domain, wordlist=wordlist)
    return read_lines_file(out_path) if out_path else []


def harvest_enumerator_outputs(
    domain: str,
    config: Dict[str, Any],
    seen_cache: Dict[str, set],
    job_domain: Optional[str] = None,
) -> bool:
    """增量收割 dnsx 爆破输出.

    Args:
        domain: 目标.
        config: 运行配置.
        seen_cache: 已见主机集合.
        job_domain: 可选 job 日志.

    Returns:
        bool: 是否写入了新主机.

    Raises:
        无.
    """
    job_pause_point(job_domain)
    state = None

    def ensure_state():
        nonlocal state
        if state is None:
            state = load_state()
        return state

    if not config.get("enable_dnsx", True):
        return False
    path = _artifact_path(domain, "dnsx_brute", ".txt")
    if not path.exists():
        path = _artifact_path(domain, "dnsx", ".txt")
    if not path.exists():
        return False
    try:
        subs = read_lines_file(path)
    except Exception as exc:
        log(f"Error parsing {path}: {exc}")
        return False
    cache = seen_cache.setdefault("dnsx", set())
    new_items = [s for s in subs if s not in cache]
    if not new_items:
        return False
    cache.update(new_items)
    add_subdomains_to_state(ensure_state(), domain, new_items, "dnsx")
    job_log_append(job_domain, f"dnsx added {len(new_items)} new subdomains.", "dnsx")
    save_state(state)
    return True



def port_scan_hosts(
    hosts: List[str],
    domain: str,
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
) -> List[Any]:
    """对主机/网段做 nmap 服务探测.

    Args:
        hosts: IP、CIDR 或主机名.
        domain: 目标标识.
        config: 含 port_scan_ports.
        job_domain: 可选 job 日志.

    Returns:
        List[HostPorts]: 开放端口主机. 失败返回空列表.

    Raises:
        无.
    """
    cleaned = [h.strip() for h in hosts if h and str(h).strip()]
    if not cleaned:
        return []
    if not ensure_tool_installed("nmap"):
        log("nmap not installed; port scan skipped.")
        if job_domain:
            job_log_append(job_domain, "nmap not installed; port scan skipped.", "port_scan")
        return []
    cfg = config if config is not None else get_config()
    xml_path = _artifact_path(domain, "nmap", ".xml")
    ports = str(cfg.get("port_scan_ports") or DEFAULT_PORT_SPEC)
    try:
        cmd = build_nmap_command(TOOLS["nmap"], cleaned, str(xml_path), ports=ports)
    except ValueError as exc:
        log(f"nmap command build failed: {exc}")
        return []
    context = {"DOMAIN": domain, "OUTPUT": str(xml_path), "PORTS": ports}
    cmd = apply_template_flags("nmap", cmd, context, cfg)
    if job_domain:
        job_log_append(job_domain, "Waiting for nmap slot...", "scheduler")
    with TOOL_GATES["nmap"]:
        if job_domain:
            job_log_append(job_domain, "nmap slot acquired.", "scheduler")
        run_subprocess(cmd, job_domain=job_domain, step="port_scan")
    if not xml_path.exists():
        return []
    try:
        xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log(f"Failed reading nmap XML: {exc}")
        return []
    return parse_nmap_xml(xml_text)


def enrich_state_with_ports(state: Dict[str, Any], domain: str, hosts: List[Any]) -> List[str]:
    """把 nmap 结果写入目标资产, 返回应做 HTTP 探测的 URL.

    Args:
        state: 全局 state.
        domain: 目标.
        hosts: parse_nmap_xml 结果.

    Returns:
        List[str]: web URL 列表.

    Raises:
        无.
    """
    identities: List[str] = []
    for host in hosts:
        identities.extend(host.identities())
        add_subdomains_to_state(state, domain, host.identities(), "nmap")
        tgt = ensure_target_state(state, domain)
        for name in host.identities():
            entry = tgt["subdomains"].setdefault(name, make_subdomain_entry())
            entry["ip"] = host.ip
            entry["ports"] = [p.to_dict() for p in host.ports]
    endpoints = web_endpoints_from_hosts(hosts)
    urls = []
    seen = set()
    for item in endpoints:
        url = item.get("url") or ""
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
        host_name = (item.get("host") or "").strip().lower()
        if host_name:
            add_subdomains_to_state(state, domain, [host_name], "nmap")
    return urls


def vhost_enum_web_services(
    domain: str,
    web_urls: List[str],
    wordlist: Optional[str],
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
) -> List[str]:
    """对 Web 入口做 Host 头 vhost 爆破.

    Args:
        domain: 任务目标, 域名时作为 FUZZ.domain.
        web_urls: http(s) URL.
        wordlist: 字典路径.
        config: 含 vhost_max_targets.
        job_domain: 可选 job 日志.

    Returns:
        List[str]: 发现的 Host 名.

    Raises:
        无.
    """
    if not web_urls:
        return []
    if not ensure_tool_installed("ffuf"):
        return []
    cfg = config if config is not None else get_config()
    resolved = resolve_wordlist_path(wordlist or cfg.get("default_wordlist") or "")
    if not resolved or not Path(resolved).is_file():
        log("vhost enum skipped: wordlist not found")
        if job_domain:
            job_log_append(job_domain, "vhost enum skipped: wordlist not found", "vhost_enum")
        return []
    parsed_target = parse_scan_target(domain)
    base_domain = parsed_target.normalized if parsed_target and parsed_target.kind == TargetKind.DOMAIN else None
    host_pattern = vhost_host_pattern(base_domain)
    try:
        max_targets = max(1, min(200, int(cfg.get("vhost_max_targets") or 20)))
    except (TypeError, ValueError):
        max_targets = 20
    unique_urls: List[str] = []
    seen = set()
    for url in web_urls:
        item = (url or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        unique_urls.append(item)
        if len(unique_urls) >= max_targets:
            break
    found: List[str] = []
    found_set = set()
    for index, url in enumerate(unique_urls):
        out_json = _artifact_path(domain, f"ffuf_vhost_{index}", ".json")
        try:
            cmd = build_ffuf_vhost_command(
                TOOLS["ffuf"], url, resolved, str(out_json), host_pattern=host_pattern
            )
        except ValueError as exc:
            log(f"ffuf vhost command failed: {exc}")
            continue
        context = {
            "DOMAIN": domain,
            "WORDLIST": resolved,
            "OUTPUT": str(out_json),
            "TARGET_URL": url,
            "HOST_HEADER": host_pattern,
        }
        cmd = apply_template_flags("ffuf", cmd, context, cfg)
        if job_domain:
            job_log_append(job_domain, f"vhost enum {url} Host: {host_pattern}", "vhost_enum")
        with TOOL_GATES["ffuf"]:
            run_subprocess(cmd, job_domain=job_domain, step="vhost_enum")
        if not out_json.exists():
            continue
        try:
            text = out_json.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for hit in parse_ffuf_vhost_json(text, host_pattern):
            host = hit.host.strip().lower()
            if not host or host in found_set:
                continue
            if not is_valid_subdomain(host) and parse_scan_target(host) is None:
                continue
            found_set.add(host)
            found.append(host)
    return found


# ================== JS GATHERER & SECRET/ENDPOINT SCANNER ==================
#
# Self-contained (stdlib only): fetches JS assets referenced by live hosts and
# archived endpoints, then scans them for secrets/keys, hidden endpoints and
# parameters. No external binary required.

# Secret / key patterns. Ordered most-specific first. Values are compiled below.
_JS_SECRET_PATTERN_SRC: List[Tuple[str, str]] = [
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret_access_key", r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("google_oauth_token", r"\bya29\.[0-9A-Za-z\-_]{20,}"),
    ("gcp_service_account", r"\"type\"\s*:\s*\"service_account\""),
    ("firebase_cloud_msg_key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
    ("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"),
    ("github_pat", r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+"),
    ("stripe_key", r"\b[rsp]k_live_[0-9a-zA-Z]{24,}\b"),
    ("square_token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"),
    ("twilio_sid", r"\bAC[0-9a-fA-F]{32}\b"),
    ("sendgrid_key", r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"),
    ("mailgun_key", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("npm_token", r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("basic_auth_url", r"https?://[a-zA-Z0-9._%+-]+:[^@\s/'\"]{3,}@[a-zA-Z0-9.-]+"),
    ("generic_secret",
     r"(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|auth[_-]?token|"
     r"access[_-]?token|password|passwd|bearer)[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,64})[\"']"),
]
_JS_SECRET_PATTERNS = [(name, re.compile(src)) for name, src in _JS_SECRET_PATTERN_SRC]

# Endpoint patterns: relative paths, absolute URLs, and common HTTP call sites.
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""['"](/[a-zA-Z0-9_\-./]{1,}(?:\?[a-zA-Z0-9_\-=&%.]*)?)['"]"""),
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch|open))\(\s*['"]([^'"\s]{2,200})['"]"""),
    re.compile(r"""['"](https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_\-./]*)?(?:\?[a-zA-Z0-9_\-=&%.]*)?)['"]"""),
]
_JS_PARAM_RE = re.compile(r"[?&]([a-zA-Z0-9_\-]{1,40})=")

# Placeholder values to drop from generic-secret hits (reduce false positives).
_JS_SECRET_PLACEHOLDERS = re.compile(
    r"(?i)^(?:x{3,}|y{3,}|0{3,}|your[_-]?|example|test|sample|placeholder|"
    r"changeme|none|null|undefined|false|true|abc123|xxxxxx|redacted|\.{2,})"
)
# Static-asset extensions to exclude from the endpoint list.
_JS_ASSET_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|mp3|"
    r"map|pdf|zip|gz|wasm)(?:\?|$)", re.IGNORECASE)


def _js_fetch(url: str, timeout: int = 15, max_bytes: int = 5_000_000) -> Optional[str]:
    """GET a URL, returning decoded text (bounded), or None on failure."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; subScraper-jsscan/1.0)",
            "Accept": "*/*",
        })
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_bytes + 1)
    except (HTTPError, URLError, ssl.SSLError, TimeoutError, OSError, ValueError):
        return None
    except Exception:
        return None
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace")


def _redact_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[0] + "***" if value else "***"
    return f"{value[:4]}…{value[-4:]} ({len(value)} chars)"


def scan_js_content(text: str, source: str) -> Dict[str, List[Dict[str, Any]]]:
    """Scan one JS/HTML blob for secrets, endpoints and parameters."""
    secrets: List[Dict[str, Any]] = []
    endpoints: set = set()
    params: set = set()

    for name, pattern in _JS_SECRET_PATTERNS:
        for m in pattern.finditer(text):
            captured = m.group(1) if m.groups() else m.group(0)
            if name == "generic_secret" and _JS_SECRET_PLACEHOLDERS.search(captured or ""):
                continue
            secrets.append({
                "type": name,
                "match": _redact_secret(captured or m.group(0)),
                "source": source,
            })

    for pattern in _JS_ENDPOINT_PATTERNS:
        for m in pattern.finditer(text):
            ep = (m.group(1) or "").strip()
            if len(ep) < 2 or _JS_ASSET_EXT.search(ep):
                continue
            # Skip pure MIME/type strings and template noise.
            if ep.startswith("//") or " " in ep or "${" in ep:
                continue
            endpoints.add(ep)
            for pm in _JS_PARAM_RE.finditer(ep):
                params.add(pm.group(1))

    return {
        "secrets": secrets,
        "endpoints": sorted(endpoints),
        "params": sorted(params),
    }
