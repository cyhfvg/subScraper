"""Fragment 09_expand_wildcard_targets.py. Loaded into the main module namespace."""
def expand_wildcard_targets(raw: str, config: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Expand wildcard targets from input string. Supports multiple domains
    separated by commas or newlines.
    
    Examples:
      Single domain: "example.com"
      Wildcard: "*.example.com"
      TLD wildcard: "example.*"
      Multiple domains: "example.com, test.com" or "example.com\ntest.com"
      Multiple wildcards: "*.example.com\n*.test.com"
    """
    # Parse multiple domains from input
    domain_inputs = _parse_multiple_domains(raw)
    if not domain_inputs:
        return []
    
    all_candidates: List[str] = []
    
    # Process each domain input
    for domain_input in domain_inputs:
        normalized = _sanitize_domain_input(domain_input)
        if not normalized:
            continue
        
        while normalized.startswith("*."):
            normalized = normalized[2:]
        trailing_any_tld = normalized.endswith(".*")
        if trailing_any_tld:
            normalized = normalized[:-2]
        normalized = normalized.strip(".")
        if not normalized:
            continue
        
        # Expand TLD wildcards if present
        if trailing_any_tld:
            cfg = config or get_config()
            tlds = _normalize_tld_list(cfg.get("wildcard_tlds"))
            for suffix in tlds:
                if not suffix:
                    continue
                all_candidates.append(f"{normalized}.{suffix}")
        else:
            all_candidates.append(normalized)
    
    # Deduplicate results
    deduped: List[str] = []
    seen: set = set()
    for candidate in all_candidates:
        cleaned = candidate.strip(".")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return deduped


def update_config_settings(values: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    cfg = get_config()
    changed = False

    if "default_wordlist" in values:
        new_wordlist = str(values.get("default_wordlist") or "").strip()
        if cfg.get("default_wordlist", "") != new_wordlist:
            cfg["default_wordlist"] = new_wordlist
            changed = True

    if "default_interval" in values:
        try:
            new_interval = max(5, int(values.get("default_interval")))
        except (TypeError, ValueError):
            return False, "Default interval must be an integer >= 5.", cfg
        if cfg.get("default_interval") != new_interval:
            cfg["default_interval"] = new_interval
            changed = True

    if "wildcard_tlds" in values:
        new_tlds = _normalize_tld_list(values.get("wildcard_tlds"))
        if cfg.get("wildcard_tlds", []) != new_tlds:
            cfg["wildcard_tlds"] = new_tlds
            changed = True

    if "dns_resolvers" in values:
        new_resolvers = _normalize_resolver_list(values.get("dns_resolvers"))
        if cfg.get("dns_resolvers", []) != new_resolvers:
            cfg["dns_resolvers"] = new_resolvers
            changed = True


    if "skip_nikto_by_default" in values:
        new_skip = bool_from_value(
            values.get("skip_nikto_by_default"),
            cfg.get("skip_nikto_by_default", False)
        )
        if cfg.get("skip_nikto_by_default") != new_skip:
            cfg["skip_nikto_by_default"] = new_skip
            changed = True

    if "enable_amass" in values:
        new_amass = bool_from_value(values.get("enable_amass"), cfg.get("enable_amass", True))
        if cfg.get("enable_amass", True) != new_amass:
            cfg["enable_amass"] = new_amass
            changed = True

    for key in ["enable_subfinder", "enable_assetfinder", "enable_findomain", "enable_sublist3r", "enable_screenshots", "enable_crtsh", "enable_github_subdomains", "enable_dnsx", "enable_waybackurls", "enable_gau", "enable_js_scan",
                "use_bundled_nuclei_templates"]:
        if key in values:
            new_value = bool_from_value(values.get(key), cfg.get(key, True))
            if cfg.get(key, True) != new_value:
                cfg[key] = new_value
                changed = True

    # Handle global rate limit (can be 0 or positive float)
    if "global_rate_limit" in values:
        try:
            new_rate_limit = max(0.0, float(values.get("global_rate_limit")))
        except (TypeError, ValueError):
            return False, "Global rate limit must be a number >= 0.", cfg
        if cfg.get("global_rate_limit", 0.0) != new_rate_limit:
            cfg["global_rate_limit"] = new_rate_limit
            changed = True

    concurrency_fields = {
        "max_running_jobs": "Max concurrent jobs",  # not inheritable: jobs, not tools
        "max_parallel_amass": "Amass parallel slots",
        "max_parallel_subfinder": "Subfinder parallel slots",
        "max_parallel_assetfinder": "Assetfinder parallel slots",
        "max_parallel_findomain": "Findomain parallel slots",
        "max_parallel_sublist3r": "Sublist3r parallel slots",
        "max_parallel_crtsh": "Crt.sh parallel slots",
        "max_parallel_github_subdomains": "GitHub-Subdomains parallel slots",
        "max_parallel_dnsx": "DNSx parallel slots",
        "max_parallel_httpx": "HTTPx parallel slots",
        "max_parallel_ffuf": "FFUF parallel slots",
        "max_parallel_waybackurls": "Waybackurls parallel slots",
        "max_parallel_gau": "GAU parallel slots",
        "max_parallel_nuclei": "Nuclei parallel slots",
        "max_parallel_nikto": "Nikto parallel slots",
        "max_parallel_gowitness": "Screenshot parallel slots",
        "subfinder_threads": "Subfinder threads",
        "assetfinder_threads": "Assetfinder threads",
        "findomain_threads": "Findomain threads",
        "amass_timeout": "Amass timeout (seconds)",
    }
    for field, label in concurrency_fields.items():
        if field in values:
            raw_value = values.get(field)
            # A blank or 0 per-tool slot count means "use default_tool_workers".
            inheritable = field.startswith("max_parallel_")
            if inheritable and raw_value in (None, "", "0", 0):
                new_limit = 0
            else:
                try:
                    new_limit = max(1, min(MAX_TOOL_WORKERS if inheritable else 1000, int(raw_value)))
                except (TypeError, ValueError):
                    suffix = " (or 0 to use the default)" if inheritable else ""
                    return False, f"{label} must be an integer >= 1{suffix}.", cfg
            if cfg.get(field, 1) != new_limit:
                cfg[field] = new_limit
                changed = True

    if "default_tool_workers" in values:
        try:
            new_workers = max(1, min(MAX_TOOL_WORKERS, int(values.get("default_tool_workers"))))
        except (TypeError, ValueError):
            return False, f"Workers per tool must be an integer between 1 and {MAX_TOOL_WORKERS}.", cfg
        if cfg.get("default_tool_workers", DEFAULT_TOOL_WORKERS) != new_workers:
            cfg["default_tool_workers"] = new_workers
            changed = True

    if "tool_flag_templates" in values:
        new_templates = _normalize_tool_flag_templates(values.get("tool_flag_templates"))
        if cfg.get("tool_flag_templates", {}) != new_templates:
            cfg["tool_flag_templates"] = new_templates
            changed = True
    
    # Handle dynamic mode settings
    if "dynamic_mode_enabled" in values:
        new_dynamic = bool_from_value(values.get("dynamic_mode_enabled"), cfg.get("dynamic_mode_enabled", False))
        if cfg.get("dynamic_mode_enabled", False) != new_dynamic:
            cfg["dynamic_mode_enabled"] = new_dynamic
            changed = True
    
    dynamic_mode_fields = {
        "dynamic_mode_base_jobs": "Dynamic mode base jobs",
        "dynamic_mode_max_jobs": "Dynamic mode max jobs",
    }
    for field, label in dynamic_mode_fields.items():
        if field in values:
            try:
                new_limit = max(1, int(values.get(field)))
            except (TypeError, ValueError):
                return False, f"{label} must be an integer >= 1.", cfg
            if cfg.get(field, 1) != new_limit:
                cfg[field] = new_limit
                changed = True
    
    # Handle dynamic mode threshold settings
    if "dynamic_mode_cpu_threshold" in values:
        try:
            new_threshold = max(0.0, min(100.0, float(values.get("dynamic_mode_cpu_threshold"))))
        except (TypeError, ValueError):
            return False, "CPU threshold must be a number between 0 and 100.", cfg
        if cfg.get("dynamic_mode_cpu_threshold", 75.0) != new_threshold:
            cfg["dynamic_mode_cpu_threshold"] = new_threshold
            changed = True
    
    if "dynamic_mode_memory_threshold" in values:
        try:
            new_threshold = max(0.0, min(100.0, float(values.get("dynamic_mode_memory_threshold"))))
        except (TypeError, ValueError):
            return False, "Memory threshold must be a number between 0 and 100.", cfg
        if cfg.get("dynamic_mode_memory_threshold", 80.0) != new_threshold:
            cfg["dynamic_mode_memory_threshold"] = new_threshold
            changed = True
    
    # Handle auto-backup settings
    if "auto_backup_enabled" in values:
        new_auto_backup = bool_from_value(values.get("auto_backup_enabled"), cfg.get("auto_backup_enabled", False))
        if cfg.get("auto_backup_enabled", False) != new_auto_backup:
            cfg["auto_backup_enabled"] = new_auto_backup
            changed = True
    
    if "auto_backup_interval" in values:
        try:
            new_interval = max(300, int(values.get("auto_backup_interval")))  # Min 5 minutes
        except (TypeError, ValueError):
            return False, "Auto-backup interval must be an integer >= 300 seconds (5 minutes).", cfg
        if cfg.get("auto_backup_interval", 3600) != new_interval:
            cfg["auto_backup_interval"] = new_interval
            changed = True
    
    if "auto_backup_max_count" in values:
        try:
            new_count = max(1, int(values.get("auto_backup_max_count")))
        except (TypeError, ValueError):
            return False, "Auto-backup max count must be an integer >= 1.", cfg
        if cfg.get("auto_backup_max_count", 10) != new_count:
            cfg["auto_backup_max_count"] = new_count
            changed = True
    
    # Handle custom tool binary paths
    if "tool_binary_paths" in values:
        new_paths = values.get("tool_binary_paths", {})
        if isinstance(new_paths, dict):
            # Validate that paths exist
            validated_paths = {}
            for tool, path in new_paths.items():
                if tool in TOOLS and path:
                    path_obj = Path(path)
                    if path_obj.exists():
                        validated_paths[tool] = str(path_obj.resolve())
                    else:
                        log(f"Warning: Custom path for {tool} does not exist: {path}")
            
            if cfg.get("tool_binary_paths", {}) != validated_paths:
                cfg["tool_binary_paths"] = validated_paths
                changed = True

    if changed:
        save_config(cfg)
        return True, "Settings updated.", cfg
    return True, "No changes applied.", cfg


def _pid_alive(pid: int) -> bool:
    """True if a process with pid exists (signal 0 probe)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user
        return True
    except OSError:
        return False


# Consider a lock stale if its holder is dead, or it's older than this many
# seconds regardless (guards against unknown-holder / clock-skew cases).
LOCK_STALE_SECONDS = 300


def _lock_is_stale() -> bool:
    """A lock is stale if the recorded PID is dead or the file is too old."""
    try:
        raw = Path(LOCK_FILE).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    # Content is "<pid>\n<epoch>"; tolerate legacy empty locks via mtime.
    pid = 0
    if raw:
        try:
            pid = int(raw.splitlines()[0])
        except (ValueError, IndexError):
            pid = 0
    if pid and not _pid_alive(pid):
        return True
    try:
        age = time.time() - os.path.getmtime(LOCK_FILE)
    except OSError:
        return False
    return age > LOCK_STALE_SECONDS


def _steal_lock() -> bool:
    """Remove a lock we believe is stale. Return True if we removed it."""
    try:
        os.unlink(LOCK_FILE)
        return True
    except FileNotFoundError:
        return True  # someone else released it; retry acquire
    except OSError:
        return False


def acquire_lock(timeout: int = 30) -> None:
    """
    Simple file lock with exponential backoff and stale-lock recovery.

    Writes the owning PID + timestamp into the lock file so a crashed holder's
    lock can be detected (dead PID) and reclaimed instead of blocking the full
    timeout and then proceeding without ownership (which risked concurrent
    writes / corruption).
    """
    start = time.time()
    retry_delay = 0.1  # Start with 100ms
    max_retry_delay = 2.0  # Cap at 2 seconds
    payload = f"{os.getpid()}\n{int(time.time())}".encode("utf-8")

    while True:
        try:
            # use exclusive create
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            return
        except FileExistsError:
            # Reclaim a lock left behind by a dead/crashed process.
            if _lock_is_stale() and _steal_lock():
                log("Reclaimed stale lock; retrying acquire.")
                continue
            elapsed = time.time() - start
            if elapsed > timeout:
                # Last resort: force-steal so we hold the lock rather than
                # writing without ownership.
                if _steal_lock():
                    log("Lock timeout reached; force-reclaimed lock.")
                    continue
                log("Lock timeout reached, proceeding anyway (best effort).")
                return
            time.sleep(retry_delay)
            # Exponential backoff: increase delay for next retry
            retry_delay = min(retry_delay * 1.5, max_retry_delay)


def release_lock() -> None:
    try:
        LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def load_state() -> Dict[str, Any]:
    """
    Load state (targets and subdomains) from SQLite database.
    
    Optimizations:
    - Uses single JOIN query instead of N+1 queries for better performance
    - Processes results in a single pass
    """
    db = get_db()
    cursor = db.cursor()
    
    # OPTIMIZATION: Single query with JOIN instead of N+1 queries
    cursor.execute("""
        SELECT
            t.domain, t.flags, t.options, t.comments, t.data,
            s.subdomain, s.data, s.interesting, s.comments as sub_comments
        FROM targets t
        LEFT JOIN subdomains s ON t.domain = s.domain
        ORDER BY t.domain, s.subdomain
    """)
    
    targets = {}
    current_domain = None
    current_target = None
    subdomains = {}
    
    # Process results in a single pass
    for row in cursor:
        domain = row[0]
        
        # Check if we've moved to a new domain
        if domain != current_domain:
            # Save previous domain's data if exists
            if current_domain is not None:
                current_target["subdomains"] = subdomains
                targets[current_domain] = current_target
            
            # Start new domain
            current_domain = domain
            flags = json.loads(row[1]) if row[1] else {}
            options = json.loads(row[2]) if row[2] else {}
            target_comments = json.loads(row[3]) if row[3] else []
            # Extra target payload (endpoints, js_scan, ...) lives in targets.data
            try:
                extra = json.loads(row[4]) if row[4] else {}
            except json.JSONDecodeError:
                extra = {}
            if not isinstance(extra, dict):
                extra = {}
            
            current_target = {
                "flags": flags,
                "options": options,
                "comments": target_comments,
            }
            for key, value in extra.items():
                if key not in ("flags", "options", "comments", "subdomains"):
                    current_target[key] = value
            subdomains = {}
        
        # Process subdomain if present (LEFT JOIN may have NULL subdomain)
        subdomain = row[5]
        if subdomain is not None:
            try:
                sub_data = json.loads(row[6])
                # Add interesting and comments to subdomain data
                if row[7] is not None:
                    sub_data["interesting"] = bool(row[7])
                if row[8]:
                    sub_data["comments"] = json.loads(row[8])
                subdomains[subdomain] = sub_data
            except json.JSONDecodeError:
                subdomains[subdomain] = {}
    
    # Save last domain's data
    if current_domain is not None:
        current_target["subdomains"] = subdomains
        targets[current_domain] = current_target
    
    # Get last updated time from the most recent target update
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    return {
        "version": 1,
        "targets": targets,
        "last_updated": last_updated
    }
