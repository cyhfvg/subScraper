"""Fragment 14_findomain_enum.py. Loaded into the main module namespace."""
def findomain_enum(domain: str, config: Optional[Dict[str, Any]] = None, job_domain: Optional[str] = None) -> List[str]:
    if not ensure_tool_installed("findomain"):
        return []
    out_path = DATA_DIR / f"findomain_{domain}.txt"
    threads = 40
    if config:
        try:
            threads = max(1, int(config.get("findomain_threads", threads)))
        except (TypeError, ValueError):
            threads = 40
    
    # Newer versions of findomain use different output handling
    # Instead of --output, we use output redirection
    cmd = [
        TOOLS["findomain"],
        "--target", domain,
        "--threads", str(threads),
        "--quiet",
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
        "THREADS": threads,
    }
    cmd = apply_template_flags("findomain", cmd, context, config)
    
    # Use output redirection instead of --output flag
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="findomain")
    return read_lines_file(out_path) if success else []


def sublist3r_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    if not ensure_tool_installed("sublist3r"):
        return []
    out_path = DATA_DIR / f"sublist3r_{domain}.txt"
    cmd = [
        TOOLS["sublist3r"],
        "-d", domain,
        "-o", str(out_path),
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("sublist3r", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="sublist3r")
    return read_lines_file(out_path) if success else []


def crtsh_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Query crt.sh for certificate transparency logs to find subdomains.
    """
    out_path = DATA_DIR / f"crtsh_{domain}.txt"
    subs = set()
    try:
        import urllib.request
        import json as json_lib
        import ssl
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconTool/1.0"})
        if job_domain:
            job_log_append(job_domain, f"Querying crt.sh for {domain}", source="crtsh")
        
        # Create SSL context that doesn't verify certificates
        # SECURITY NOTE: This is needed because crt.sh may be behind proxies with self-signed certs.
        # The data from crt.sh is public certificate transparency logs, so the risk is limited to
        # potential MITM attacks affecting subdomain enumeration accuracy, not credential exposure.
        # For production use, consider implementing certificate pinning for crt.sh's actual cert.
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
            data = response.read()
        entries = json_lib.loads(data)
        for entry in entries:
            name = entry.get("name_value", "")
            if name:
                for line in name.split("\n"):
                    cleaned = line.strip().lower().lstrip("*.")
                    if cleaned and domain in cleaned:
                        subs.add(cleaned)
        with open(out_path, "w", encoding="utf-8") as f:
            for sub in sorted(subs):
                f.write(sub + "\n")
        if job_domain:
            job_log_append(job_domain, f"crt.sh found {len(subs)} subdomains", source="crtsh")
    except Exception as exc:
        log(f"crt.sh enumeration failed for {domain}: {exc}")
        if job_domain:
            job_log_append(job_domain, f"crt.sh error: {exc}", source="crtsh")
        # Track timeout/rate-limit errors for intelligent backoff
        track_timeout_error(domain, exc, job_domain)
    return sorted(subs)


def github_subdomains_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use github-subdomains tool to find subdomains via GitHub.
    Requires GitHub token - will try to use token from subfinder config if available.
    """
    if not ensure_tool_installed("github-subdomains"):
        return []
    
    # Try to get GitHub token from subfinder config
    github_token = None
    try:
        subfinder_keys = read_subfinder_api_keys()
        github_token = subfinder_keys.get("github", "").strip()
    except Exception:
        pass
    
    # If no token available, skip with warning
    if not github_token:
        if job_domain:
            job_log_append(job_domain, 
                "github-subdomains: No GitHub token configured. Add token in API Keys settings.", 
                source="github-subdomains")
        log(f"github-subdomains: Skipping {domain} - no GitHub token configured")
        return []
    
    out_path = DATA_DIR / f"github_subdomains_{domain}.txt"
    
    # Use environment variable to pass token securely (avoid exposing in process list)
    env = os.environ.copy()
    
    # Create temporary token file to avoid exposing token in command line
    import tempfile
    token_file = None
    try:
        # Create temporary file for token
        fd, token_file = tempfile.mkstemp(prefix="github_token_", suffix=".txt", dir=DATA_DIR)
        with os.fdopen(fd, 'w') as f:
            f.write(github_token)
        
        cmd = [
            TOOLS["github-subdomains"],
            "-d", domain,
            "-t", token_file,  # Use token file instead of raw token
            "-o", str(out_path),
        ]
        context = {
            "DOMAIN": domain,
            "OUTPUT": str(out_path),
        }
        cmd = apply_template_flags("github-subdomains", cmd, context)
        success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="github-subdomains")
        return read_lines_file(out_path) if success else []
    finally:
        # Clean up token file
        if token_file and os.path.exists(token_file):
            try:
                os.unlink(token_file)
            except Exception:
                pass


def dnsx_verify(subdomains: List[str], domain: str, job_domain: Optional[str] = None,
                config: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Use dnsx to verify which subdomains actually resolve.
    """
    if not ensure_tool_installed("dnsx"):
        return subdomains
    if not subdomains:
        return []

    input_path = DATA_DIR / f"dnsx_input_{domain}.txt"
    out_path = DATA_DIR / f"dnsx_{domain}.txt"

    with open(input_path, "w", encoding="utf-8") as f:
        for sub in subdomains:
            f.write(sub + "\n")

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
        cmd.extend(["-rL", str(rf)])
        if job_domain:
            job_log_append(job_domain, f"DNSx DNS resolvers: {', '.join(resolvers)}", "dnsx")
    context = {
        "DOMAIN": domain,
        "INPUT": str(input_path),
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("dnsx", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="dnsx")
    return read_lines_file(out_path) if success else subdomains



def waybackurls_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use waybackurls to discover URLs from archive.org.
    """
    if not ensure_tool_installed("waybackurls"):
        return []
    out_path = DATA_DIR / f"waybackurls_{domain}.txt"
    cmd = [
        TOOLS["waybackurls"],
        domain,
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("waybackurls", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="waybackurls")
    return read_lines_file(out_path) if success else []


def gau_enum(domain: str, job_domain: Optional[str] = None) -> List[str]:
    """
    Use gau (Get All URLs) to discover URLs from various sources.
    """
    if not ensure_tool_installed("gau"):
        return []
    out_path = DATA_DIR / f"gau_{domain}.txt"
    cmd = [
        TOOLS["gau"],
        "--subs",
        domain,
    ]
    context = {
        "DOMAIN": domain,
        "OUTPUT": str(out_path),
    }
    cmd = apply_template_flags("gau", cmd, context)
    success = run_subprocess(cmd, outfile=out_path, job_domain=job_domain, step="gau")
    return read_lines_file(out_path) if success else []


def harvest_enumerator_outputs(
    domain: str,
    config: Dict[str, Any],
    seen_cache: Dict[str, set],
    job_domain: Optional[str] = None,
) -> bool:
    job_pause_point(job_domain)
    state = None
    added = False

    def ensure_state():
        nonlocal state
        if state is None:
            state = load_state()
        return state

    def process(name: str, enabled: bool, path: Path, parser):
        nonlocal added
        if not enabled:
            return
        if not path.exists():
            return
        try:
            subs = parser(path)
        except Exception as exc:
            log(f"Error parsing {path}: {exc}")
            return
        cache = seen_cache.setdefault(name, set())
        new_items = [s for s in subs if s not in cache]
        if not new_items:
            return
        cache.update(new_items)
        add_subdomains_to_state(ensure_state(), domain, new_items, name)
        job_log_append(job_domain, f"{name} added {len(new_items)} new subdomains.", name)
        added = True

    amass_enabled = config.get("enable_amass", True)
    process(
        "amass",
        amass_enabled,
        DATA_DIR / f"amass_{domain}.json",
        parse_amass_json,
    )
    process(
        "subfinder",
        config.get("enable_subfinder", True),
        DATA_DIR / f"subfinder_{domain}.txt",
        read_lines_file,
    )
    process(
        "assetfinder",
        config.get("enable_assetfinder", True),
        DATA_DIR / f"assetfinder_{domain}.txt",
        read_lines_file,
    )
    process(
        "findomain",
        config.get("enable_findomain", True),
        DATA_DIR / f"findomain_{domain}.txt",
        read_lines_file,
    )
    process(
        "sublist3r",
        config.get("enable_sublist3r", True),
        DATA_DIR / f"sublist3r_{domain}.txt",
        read_lines_file,
    )
    process(
        "crtsh",
        config.get("enable_crtsh", True),
        DATA_DIR / f"crtsh_{domain}.txt",
        read_lines_file,
    )
    process(
        "github-subdomains",
        config.get("enable_github_subdomains", True),
        DATA_DIR / f"github_subdomains_{domain}.txt",
        read_lines_file,
    )

    if added and state is not None:
        save_state(state)
    return added


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
