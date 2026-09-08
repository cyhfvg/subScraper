"""Fragment 17_run_batch_sharded.py. Loaded into the main module namespace."""
def run_batch_sharded(tool: str, hosts: List[str], domain: str,
                      scanner, config: Optional[Dict[str, Any]] = None,
                      job_domain: Optional[str] = None) -> Optional[Path]:
    """
    Run a batch tool over `hosts` using its configured worker count: the host
    list is split, each shard gets its own input file, its own process and its
    own gate slot, and the JSONL outputs are merged back into the single file
    the rest of the pipeline expects.
    """
    if not hosts:
        return None
    destination = DATA_DIR / f"{tool}_{domain}.json"
    shard_index = {"n": 0}
    lock = threading.Lock()

    def run_shard(chunk: List[str]) -> Optional[Path]:
        with lock:
            shard_index["n"] += 1
            index = shard_index["n"]
        suffix = f"_w{index}"
        batch_file = write_subdomains_file(domain, chunk, suffix=f"_{tool}_batch{suffix}")
        try:
            return scanner(batch_file, suffix)
        finally:
            try:
                batch_file.unlink()
            except Exception:
                pass

    results = run_tool_shards(tool, hosts, run_shard, config=config, job_domain=job_domain)
    parts = [path for path in results if isinstance(path, Path)]
    if not parts:
        return None
    if len(parts) == 1 and parts[0] == destination:
        return destination
    return _merge_jsonl_files(parts, destination)


def _normalize_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def gather_screenshot_targets(state: Dict[str, Any], domain: str) -> List[Tuple[str, str]]:
    tgt = ensure_target_state(state, domain)
    submap = tgt.get("subdomains", {})
    targets: List[Tuple[str, str]] = []
    seen_urls = set()
    for host, info in submap.items():
        httpx_info = info.get("httpx") or {}
        url = httpx_info.get("url")
        if not url:
            continue
        # Only include subdomains with valid response codes (optimization)
        status_code = httpx_info.get("status_code")
        if status_code is None:
            continue
        # Filter out invalid responses (0 or no response typically means failed connection)
        if status_code == 0:
            continue
        if info.get("screenshot"):
            continue
        norm = url.strip()
        if not norm or norm in seen_urls:
            continue
        seen_urls.add(norm)
        targets.append((host, norm))
    return targets


def reconcile_screenshots_from_disk(state: Dict[str, Any], domain: str) -> int:
    """
    Attach screenshot files already on disk to subdomains missing a screenshot
    in state. Self-heals targets captured before the filename-matching fix.
    Returns the number of newly attached screenshots.
    """
    dest_dir = SCREENSHOTS_DIR / domain
    if not dest_dir.is_dir():
        return 0
    tgt = ensure_target_state(state, domain)
    submap = tgt.get("subdomains", {})
    if not submap:
        return 0

    # Build host-key -> (path, mtime) from files on disk.
    file_index: Dict[str, Tuple[Path, float]] = {}
    for extension in ["*.jpeg", "*.jpg", "*.png"]:
        for path in dest_dir.rglob(extension):
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            keys = {_normalize_identifier(path.stem)}
            for host_key in _screenshot_host_keys(path.stem):
                keys.add(host_key)
            for key in keys:
                if not key:
                    continue
                existing = file_index.get(key)
                if existing is None or mtime > existing[1]:
                    file_index[key] = (path, mtime)

    if not file_index:
        return 0

    attached = 0
    for host, entry in submap.items():
        if not isinstance(entry, dict) or entry.get("screenshot"):
            continue
        httpx = entry.get("httpx") or {}
        candidates = [_normalize_identifier(host)]
        url = httpx.get("url")
        if url:
            candidates.insert(0, _normalize_identifier(url))
        match: Optional[Path] = None
        for cand in candidates:
            found = file_index.get(cand)
            if found:
                match = found[0]
                break
        if not match or not match.exists():
            continue
        try:
            rel_path = match.relative_to(SCREENSHOTS_DIR)
        except ValueError:
            rel_path = match
        try:
            captured = datetime.fromtimestamp(
                match.stat().st_mtime, tz=timezone.utc
            ).isoformat()
        except OSError:
            captured = datetime.now(timezone.utc).isoformat()
        entry["screenshot"] = {
            "path": str(rel_path).replace("\\", "/"),
            "url": url or f"http://{host}",
            "captured_at": captured,
        }
        attached += 1
    return attached


def _screenshot_host_keys(stem: str) -> List[str]:
    """
    Derive normalized host keys from a gowitness screenshot filename stem.

    gowitness v3 names files like "https---youtube-ui.l.google.com-443"
    (scheme "---" host "-" port). Extract the host so it matches the target
    host/URL, and also emit the port-stripped variant for robustness.
    """
    keys: List[str] = []
    core = stem
    # Strip leading "<scheme>---" if present.
    if "---" in core:
        core = core.split("---", 1)[1]
    # Strip trailing "-<port>" if the tail looks like a port number.
    m = re.match(r"^(.*)-(\d{1,5})$", core)
    if m:
        keys.append(_normalize_identifier(m.group(1)))
    keys.append(_normalize_identifier(core))
    return [k for k in keys if k]


def capture_screenshots(
    targets: List[Tuple[str, str]],
    domain: str,
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    if not targets:
        return {}
    if not ensure_tool_installed("gowitness"):
        return {}

    dest_dir = SCREENSHOTS_DIR / domain
    dest_dir.mkdir(parents=True, exist_ok=True)
    target_file = dest_dir / f"{domain}_gowitness_targets.txt"
    db_path = dest_dir / f"{domain}_gowitness.sqlite3"
    try:
        with open(target_file, "w", encoding="utf-8") as f:
            for _, url in targets:
                f.write(url.strip() + "\n")
    except Exception as exc:
        log(f"Failed writing screenshot target file: {exc}")
        return {}

    run_started = time.time()
    cmd = [
        TOOLS["gowitness"],
        "scan",
        "file",
        "-f", str(target_file),
        "-s", str(dest_dir),
        "--write-db",
        "--write-db-uri", f"sqlite://{db_path}",
        "--quiet",
        "--timeout", "30",  # Timeout per URL to prevent getting stuck
        "--delay", "1",      # Small delay between requests
    ]
    context = {
        "DOMAIN": domain,
        "TARGETS_FILE": str(target_file),
        "OUTPUT_DIR": str(dest_dir),
        "DB_PATH": str(db_path),
    }
    cmd = apply_template_flags("gowitness", cmd, context, config)
    success = run_subprocess(cmd, job_domain=job_domain, step="screenshots")
    try:
        target_file.unlink(missing_ok=True)
    except Exception:
        pass
    if not success:
        return {}

    recent_files: Dict[str, Path] = {}
    cutoff = run_started
    # gowitness default format is jpeg, but also check for png in case format was customized
    # Check in order of preference: .jpeg, .jpg, .png
    for extension in ["*.jpeg", "*.jpg", "*.png"]:
        for path in dest_dir.rglob(extension):
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if mtime < cutoff:
                continue
            # Key by the full stem (legacy naming) and, for gowitness v3
            # filenames of the form "<scheme>---<host>-<port>", also by the
            # extracted host so URL/host lookups below can match.
            keys = {_normalize_identifier(path.stem)}
            for host_key in _screenshot_host_keys(path.stem):
                keys.add(host_key)
            for key in keys:
                if key and key not in recent_files:
                    recent_files[key] = path

    mapping: Dict[str, Dict[str, Any]] = {}
    captured_ts = datetime.now(timezone.utc).isoformat()
    for host, url in targets:
        normalized_candidates = [
            _normalize_identifier(url),
            _normalize_identifier(host),
        ]
        screenshot_path: Optional[Path] = None
        for candidate in normalized_candidates:
            screenshot_path = recent_files.get(candidate)
            if screenshot_path:
                break
        if not screenshot_path or not screenshot_path.exists():
            continue
        try:
            rel_path = screenshot_path.relative_to(SCREENSHOTS_DIR)
        except ValueError:
            rel_path = screenshot_path
        mapping[host] = {
            "path": str(rel_path).replace("\\", "/"),
            "url": url,
            "captured_at": captured_ts,
        }
    return mapping


def bundled_nuclei_templates() -> List[Path]:
    """YAML templates shipped in this repository."""
    if not BUNDLED_NUCLEI_TEMPLATES_DIR.exists():
        return []
    return sorted(BUNDLED_NUCLEI_TEMPLATES_DIR.rglob("*.yaml"))


def nuclei_default_templates_dir() -> Optional[Path]:
    """
    Where nuclei keeps the official template set. Needed because passing -t
    switches nuclei to *only* those paths, so the default directory has to be
    passed explicitly alongside the bundled one.
    """
    config_files = [
        Path.home() / ".config" / "nuclei" / "config.yaml",
        Path.home() / ".config" / "nuclei" / ".templates-config.json",
    ]
    for config_file in config_files:
        try:
            if not config_file.exists():
                continue
            text = config_file.read_text(encoding="utf-8", errors="replace")
            match = re.search(r'"?(?:templates-directory|nuclei-templates-directory)"?\s*[:=]\s*"?([^"\n,}]+)',
                              text)
            if match:
                candidate = Path(match.group(1).strip()).expanduser()
                if candidate.is_dir():
                    return candidate
        except Exception:
            continue

    for candidate in (Path.home() / ".local" / "nuclei-templates",
                      Path.home() / "nuclei-templates",
                      Path("/root/nuclei-templates"),
                      Path("/opt/nuclei-templates")):
        if candidate.is_dir():
            return candidate
    return None


def nuclei_template_args(config: Optional[Dict[str, Any]] = None,
                         job_domain: Optional[str] = None) -> List[str]:
    """
    Build the -t arguments so a scan runs the official templates *and* the ones
    bundled here. If the official directory cannot be found we pass nothing and
    let nuclei use (and install) its defaults, rather than silently narrowing
    the scan down to the bundled handful.
    """
    cfg = config if config is not None else get_config()
    if not bool_from_value(cfg.get("use_bundled_nuclei_templates"), True):
        return []
    bundled = bundled_nuclei_templates()
    if not bundled:
        return []
    default_dir = nuclei_default_templates_dir()
    if not default_dir:
        message = (f"Bundled nuclei templates ({len(bundled)}) skipped this run: the official template "
                   "directory was not found. Run 'nuclei -update-templates' once and they will be included.")
        log(message)
        if job_domain:
            job_log_append(job_domain, message, "nuclei")
        return []
    if job_domain:
        job_log_append(job_domain,
                       f"Using {len(bundled)} bundled template(s) from nuclei-templates/ plus the official set.",
                       "nuclei")
    return ["-t", str(default_dir), "-t", str(BUNDLED_NUCLEI_TEMPLATES_DIR)]


def nuclei_scan(subs_file: Path, domain: str, config: Optional[Dict[str, Any]] = None,
                job_domain: Optional[str] = None, out_suffix: str = "") -> Path:
    if not ensure_tool_installed("nuclei"):
        return None
    out_json = DATA_DIR / f"nuclei_{domain}{out_suffix}.json"
    cmd = [
        TOOLS["nuclei"],
        "-l", str(subs_file),
        "-jsonl",
    ]
    cmd.extend(nuclei_template_args(config, job_domain))
    context = {
        "DOMAIN": domain,
        "INPUT_FILE": str(subs_file),
        "OUTPUT": str(out_json),
    }
    cmd = apply_template_flags("nuclei", cmd, context, config)
    success = run_subprocess(cmd, outfile=out_json, job_domain=job_domain, step="nuclei")
    return out_json if success and out_json.exists() else None


def _normalize_nikto_severity(value: Any, message: Optional[str] = None) -> str:
    if value is None:
        text = ""
    else:
        text = str(value).strip().lower()
    numeric_map = {
        "0": "INFO",
        "1": "LOW",
        "2": "LOW",
        "3": "MEDIUM",
        "4": "HIGH",
        "5": "CRITICAL",
    }
    if text in numeric_map:
        return numeric_map[text]
    allowed = {"critical", "high", "medium", "low", "info"}
    if text in allowed:
        return text.upper()
    return "INFO"


def _parse_nikto_output(host: str, stdout_text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not stdout_text:
        return findings
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("+"):
            continue
        # Skip summary lines (e.g. "+ 0 host(s) tested")
        normalized = line.lstrip("+").strip()
        if not normalized or normalized.lower().startswith("0 host"):
            continue
        lower = normalized.lower()
        skip_prefixes = (
            "target ip",
            "target hostname",
            "target port",
            "start time",
            "end time",
            "scan terminated",
            "host(s) tested",
            "nikto",
        )
        if any(lower.startswith(prefix) for prefix in skip_prefixes):
            continue
        finding: Dict[str, Any] = {
            "host": host,
            "msg": normalized,
            "severity": _normalize_nikto_severity(None, normalized),
        }
        osvdb_match = re.search(r"OSVDB-(\d+)", normalized, re.IGNORECASE)
        if osvdb_match:
            finding["osvdb"] = osvdb_match.group(1)
        cve_match = re.search(r"CVE-\d{4}-\d+", normalized, re.IGNORECASE)
        if cve_match:
            finding["cve"] = cve_match.group(0).upper()
        uri_match = re.search(r"(?:https?://[^\s]+)", normalized, re.IGNORECASE)
        if uri_match:
            finding["uri"] = uri_match.group(0)
        findings.append(finding)
    return findings


def nikto_scan(subs: List[str], domain: str, config: Optional[Dict[str, Any]] = None,
               job_domain: Optional[str] = None) -> Path:
    if not ensure_tool_installed("nikto"):
        return None
    out_json = DATA_DIR / f"nikto_{domain}.json"

    # Nikto scans one host per process with no threading of its own, so the
    # host list is split across the configured number of workers.
    def scan_chunk(hosts: List[str]) -> List[Dict[str, Any]]:
        return _nikto_scan_hosts(hosts, domain, config=config, job_domain=job_domain)

    shard_results = run_tool_shards("nikto", list(subs), scan_chunk,
                                    config=config, job_domain=job_domain)
    results: List[Dict[str, Any]] = []
    for chunk_results in shard_results:
        if chunk_results:
            results.extend(chunk_results)

    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        log(f"Nikto scan complete: {len(results)} findings written to {out_json.name}")
        if job_domain:
            job_log_append(job_domain,
                           f"Nikto found {len(results)} total findings across {len(subs)} host(s), "
                           f"saved to {out_json.name}", source="nikto")
    except Exception as e:
        log(f"Error writing Nikto JSON: {e}")
        return None

    return out_json if out_json.exists() else None
