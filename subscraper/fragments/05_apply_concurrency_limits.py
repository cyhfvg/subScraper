"""Fragment 05_apply_concurrency_limits.py. Loaded into the main module namespace."""
def apply_concurrency_limits(cfg: Dict[str, Any]) -> None:
    global MAX_RUNNING_JOBS, GLOBAL_RATE_LIMIT_DELAY, DYNAMIC_MODE_ENABLED
    global DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS, DYNAMIC_MODE_CPU_THRESHOLD, DYNAMIC_MODE_MEMORY_THRESHOLD
    global AUTO_BACKUP_ENABLED, AUTO_BACKUP_INTERVAL, AUTO_BACKUP_MAX_COUNT
    global AUTO_CLEANUP_ENABLED, CLEANUP_SCAN_RESULTS_DAYS, CLEANUP_TEMP_FILES_HOURS, CLEANUP_INTERVAL
    
    # Apply dynamic mode settings
    try:
        DYNAMIC_MODE_ENABLED = bool(cfg.get("dynamic_mode_enabled", False))
        DYNAMIC_MODE_BASE_JOBS = max(1, int(cfg.get("dynamic_mode_base_jobs", 1)))
        DYNAMIC_MODE_MAX_JOBS = max(DYNAMIC_MODE_BASE_JOBS, int(cfg.get("dynamic_mode_max_jobs", 10)))
        DYNAMIC_MODE_CPU_THRESHOLD = max(0.0, min(100.0, float(cfg.get("dynamic_mode_cpu_threshold", 75.0))))
        DYNAMIC_MODE_MEMORY_THRESHOLD = max(0.0, min(100.0, float(cfg.get("dynamic_mode_memory_threshold", 80.0))))
    except (TypeError, ValueError):
        DYNAMIC_MODE_ENABLED = False
        DYNAMIC_MODE_BASE_JOBS = 1
        DYNAMIC_MODE_MAX_JOBS = 10
        DYNAMIC_MODE_CPU_THRESHOLD = 75.0
        DYNAMIC_MODE_MEMORY_THRESHOLD = 80.0
    
    # Apply auto-backup settings
    try:
        AUTO_BACKUP_ENABLED = bool(cfg.get("auto_backup_enabled", False))
        AUTO_BACKUP_INTERVAL = max(300, int(cfg.get("auto_backup_interval", 3600)))  # Min 5 minutes
        AUTO_BACKUP_MAX_COUNT = max(1, int(cfg.get("auto_backup_max_count", 10)))
    except (TypeError, ValueError):
        AUTO_BACKUP_ENABLED = False
        AUTO_BACKUP_INTERVAL = 3600
        AUTO_BACKUP_MAX_COUNT = 10
    
    # Apply auto-cleanup settings
    try:
        AUTO_CLEANUP_ENABLED = bool(cfg.get("auto_cleanup_enabled", True))
        CLEANUP_SCAN_RESULTS_DAYS = max(1, int(cfg.get("cleanup_scan_results_days", 30)))
        CLEANUP_TEMP_FILES_HOURS = max(1, int(cfg.get("cleanup_temp_files_hours", 24)))
        CLEANUP_INTERVAL = max(300, int(cfg.get("cleanup_interval", 3600)))  # Min 5 minutes
    except (TypeError, ValueError):
        AUTO_CLEANUP_ENABLED = True
        CLEANUP_SCAN_RESULTS_DAYS = 30
        CLEANUP_TEMP_FILES_HOURS = 24
        CLEANUP_INTERVAL = 3600
    
    # Start or stop dynamic mode worker based on config
    if DYNAMIC_MODE_ENABLED and PSUTIL_AVAILABLE:
        start_dynamic_mode_worker()
    else:
        stop_dynamic_mode_worker()
    
    # Start or stop auto-backup worker based on config
    if AUTO_BACKUP_ENABLED:
        start_auto_backup_worker()
    else:
        stop_auto_backup_worker()
    
    # Start or stop auto-cleanup worker based on config
    if AUTO_CLEANUP_ENABLED:
        start_cleanup_worker()
    else:
        stop_cleanup_worker()
    
    try:
        MAX_RUNNING_JOBS = max(1, int(cfg.get("max_running_jobs", 1)))
    except (TypeError, ValueError):
        MAX_RUNNING_JOBS = 1
    
    # Apply global rate limit
    try:
        GLOBAL_RATE_LIMIT_DELAY = max(0.0, float(cfg.get("global_rate_limit", 0.0)))
    except (TypeError, ValueError):
        GLOBAL_RATE_LIMIT_DELAY = 0.0
    
    for tool in TOOL_PARALLEL_FIELDS:
        gate = TOOL_GATES.setdefault(tool, ToolGate(DEFAULT_TOOL_WORKERS))
        gate.update_limit(tool_worker_limit(tool, cfg))
    schedule_jobs()


def is_subdomain_input(domain: str) -> bool:
    if not domain:
        return False
    parts = [part for part in domain.split(".") if part]
    return len(parts) >= 3


def job_log_append(domain: Optional[str], text: Optional[str], source: str = "system") -> None:
    if not domain or not text:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    lines = str(text).splitlines() or [str(text)]
    entries_to_store = []
    for line in lines[-200:]:
        clean = line.strip("\n")
        if not clean:
            continue
        entry = {
            "ts": timestamp,
            "source": source,
            "text": clean[:MAX_JOB_LOG_LINE_LENGTH],
        }
        entries_to_store.append(entry)
        append_domain_history(domain, entry)

    if not entries_to_store:
        return

    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if not job:
            return
        entries = job.setdefault("logs", [])
        entries.extend(entries_to_store)
        if len(entries) > MAX_JOB_LOG_LINES:
            job["logs"] = entries[-MAX_JOB_LOG_LINES:]
        else:
            job["logs"] = entries


def default_config() -> Dict[str, Any]:
    base = str(DATA_DIR.resolve())
    return {
        "data_dir": base,
        "state_file": str(STATE_FILE.resolve()),
        "dashboard_file": str(HTML_DASHBOARD_FILE.resolve()),
        "screenshots_dir": str(SCREENSHOTS_DIR.resolve()),
        "default_interval": DEFAULT_INTERVAL,
        "default_wordlist": "",
        "skip_nikto_by_default": False,
        "enable_screenshots": True,
        "enable_amass": True,
        "amass_timeout": 600,
        "dns_resolvers": [],
        "enable_subfinder": True,
        "enable_assetfinder": True,
        "enable_findomain": True,
        "enable_sublist3r": True,
        "enable_crtsh": True,
        "enable_github_subdomains": True,
        "enable_dnsx": True,
        "enable_waybackurls": True,
        "enable_gau": True,
        "enable_js_scan": True,
        "use_bundled_nuclei_templates": True,
        "js_scan_max_files": 300,
        "js_scan_max_html_hosts": 60,
        "js_scan_workers": 8,
        "wildcard_tlds": ["com", "net", "org", "io", "co", "app", "dev", "us", "uk", "in", "de"],
        "subfinder_threads": 32,
        "assetfinder_threads": 10,
        "findomain_threads": 40,
        # Workers per tool. Each max_parallel_* of 0 (the default) inherits
        # default_tool_workers, so one setting scales every tool at once.
        "default_tool_workers": DEFAULT_TOOL_WORKERS,
        "_tool_workers_migrated": False,
        "max_parallel_amass": 0,
        "max_parallel_subfinder": 0,
        "max_parallel_assetfinder": 0,
        "max_parallel_findomain": 0,
        "max_parallel_sublist3r": 0,
        "max_parallel_crtsh": 0,
        "max_parallel_github_subdomains": 0,
        "max_parallel_dnsx": 0,
        "max_parallel_ffuf": 0,
        "max_parallel_httpx": 0,
        "max_parallel_waybackurls": 0,
        "max_parallel_gau": 0,
        "max_parallel_gowitness": 0,
        "max_parallel_nuclei": 0,
        "max_parallel_nikto": 0,
        "max_running_jobs": 1,
        "global_rate_limit": 0.0,
        "tool_flag_templates": {name: "" for name in TEMPLATE_AWARE_TOOLS},
        "tool_binary_paths": {},  # Custom binary paths for tools
        "dynamic_mode_enabled": False,
        "dynamic_mode_base_jobs": 1,
        "dynamic_mode_max_jobs": 10,
        "dynamic_mode_cpu_threshold": 75.0,
        "dynamic_mode_memory_threshold": 80.0,
        "auto_backup_enabled": False,
        "auto_backup_interval": 3600,
        "auto_backup_max_count": 10,
        "auto_cleanup_enabled": True,
        "cleanup_scan_results_days": 30,
        "cleanup_temp_files_hours": 24,
        "cleanup_interval": 3600,
        "screenshots_per_page": 20,
        "setup_completed": False,
    }


# ================== MONITOR MANAGEMENT ==================


def load_monitors_state() -> Dict[str, Any]:
    """Load monitors from SQLite database."""
    ensure_dirs()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, data FROM monitors")
    rows = cursor.fetchall()
    
    monitors = {}
    for row in rows:
        monitor_id = row[0]
        try:
            monitor_data = json.loads(row[1])
            monitors[monitor_id] = monitor_data
        except json.JSONDecodeError:
            pass
    
    with MONITOR_LOCK:
        MONITOR_STATE.clear()
        MONITOR_STATE.update(monitors)
    return get_monitors_snapshot()


def _save_monitors_locked() -> None:
    """Save monitors to SQLite database (must be called with MONITOR_LOCK held)."""
    db = get_db()
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    for monitor_id, monitor_data in MONITOR_STATE.items():
        name = monitor_data.get("name", "")
        url = monitor_data.get("url", "")
        created_at = monitor_data.get("created_at", now)
        
        cursor.execute(
            """INSERT OR REPLACE INTO monitors 
               (id, name, url, data, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (monitor_id, name, url, json.dumps(monitor_data), created_at, now)
        )
    
    db.commit()


def save_monitors_state() -> None:
    """Save monitors to SQLite database."""
    ensure_dirs()
    with MONITOR_LOCK:
        _save_monitors_locked()


def get_monitors_snapshot() -> List[Dict[str, Any]]:
    with MONITOR_LOCK:
        snapshot = copy.deepcopy(MONITOR_STATE)
    return list(snapshot.values())


def list_monitors(limit_entries: int = MAX_MONITOR_ENTRIES) -> List[Dict[str, Any]]:
    with MONITOR_LOCK:
        monitors = []
        for monitor in MONITOR_STATE.values():
            data = copy.deepcopy(monitor)
            entries_map = data.get("entries") or {}
            entry_items = list(entries_map.values())
            entry_items.sort(key=lambda item: item.get("first_seen") or "", reverse=True)
            total_entries = len(entry_items)
            data["entry_count"] = total_entries
            data["pending_entries"] = sum(1 for item in entry_items if item.get("status") != "dispatched")
            if total_entries > limit_entries:
                data["entries_truncated"] = True
                entry_items = entry_items[:limit_entries]
            else:
                data["entries_truncated"] = False
            data["entries"] = entry_items
            next_ts = data.get("next_check_ts")
            if isinstance(next_ts, (int, float)):
                data["next_check"] = datetime.fromtimestamp(next_ts, tz=timezone.utc).isoformat()
            else:
                data["next_check"] = None
            monitors.append(data)
    monitors.sort(key=lambda item: item.get("name") or item.get("url") or item.get("id") or "")
    return monitors


def add_monitor(name: str, url: str, interval: Optional[int]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    cleaned_url = str(url or "").strip()
    if not cleaned_url:
        return False, "Monitor URL is required.", None
    parsed = urlparse(cleaned_url)
    if parsed.scheme not in {"http", "https"}:
        return False, "Monitor URL must start with http:// or https://", None
    try:
        interval_val = max(60, int(interval or DEFAULT_MONITOR_INTERVAL))
    except (TypeError, ValueError):
        return False, "Interval must be an integer >= 60 seconds.", None
    monitor_id = uuid.uuid4().hex
    now_iso = datetime.now(timezone.utc).isoformat()
    monitor = {
        "id": monitor_id,
        "name": (name or "").strip(),
        "url": cleaned_url,
        "interval": interval_val,
        "created_at": now_iso,
        "last_checked": None,
        "last_status": "pending",
        "last_error": "",
        "last_entry_count": 0,
        "last_new_entries": 0,
        "last_dispatch_count": 0,
        "entries": {},
        "next_check_ts": time.time(),
    }
    with MONITOR_LOCK:
        MONITOR_STATE[monitor_id] = monitor
        _save_monitors_locked()
    log(f"Added monitor {monitor_id} for {cleaned_url}")
    return True, "Monitor added.", copy.deepcopy(monitor)


def remove_monitor(monitor_id: str) -> Tuple[bool, str]:
    monitor_key = (monitor_id or "").strip()
    if not monitor_key:
        return False, "Monitor id is required."
    with MONITOR_LOCK:
        if monitor_key not in MONITOR_STATE:
            return False, "Monitor not found."
        MONITOR_STATE.pop(monitor_key, None)
        _save_monitors_locked()
    log(f"Removed monitor {monitor_key}")
    return True, "Monitor removed."


def parse_monitor_entries(text: str) -> List[str]:
    entries: List[str] = []
    if not text:
        return entries
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def fetch_monitor_source(url: str, timeout: int = 20) -> str:
    req = Request(url, headers={"User-Agent": "ReconMonitor/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="ignore")


def process_monitor(monitor_id: str) -> None:
    cfg = get_config()
    with MONITOR_LOCK:
        monitor = MONITOR_STATE.get(monitor_id)
        if not monitor:
            return
        monitor_copy = copy.deepcopy(monitor)
    url = monitor_copy.get("url")
    interval = max(60, int(monitor_copy.get("interval") or DEFAULT_MONITOR_INTERVAL))
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        content = fetch_monitor_source(url)
    except Exception as exc:
        with MONITOR_LOCK:
            target = MONITOR_STATE.get(monitor_id)
            if target:
                target["last_checked"] = now_iso
                target["last_status"] = "error"
                target["last_error"] = str(exc)
                target["next_check_ts"] = time.time() + interval
                _save_monitors_locked()
        log(f"Monitor {monitor_id} fetch failed: {exc}")
        # Track timeout/rate-limit errors for monitors
        track_timeout_error(url, exc, None)
        return
    entries = parse_monitor_entries(content)
    entries_map = monitor_copy.get("entries") or {}
    if not isinstance(entries_map, dict):
        entries_map = {}
    existing_map = {key: dict(value) for key, value in entries_map.items()}
    new_entries: List[Dict[str, Any]] = []
    for entry in entries:
        meta = existing_map.get(entry)
        if meta:
            meta["last_seen"] = now_iso
        else:
            meta = {
                "value": entry,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "status": "pending",
                "dispatch_message": "",
                "dispatch_results": [],
                "dispatched_targets": [],
                "last_dispatch": None,
            }
            existing_map[entry] = meta
            new_entries.append(meta)
    dispatched_count = 0
    skip_nikto = bool(cfg.get("skip_nikto_by_default", False))
    for meta in new_entries:
        success, message, details = start_targets_from_input(meta["value"], None, skip_nikto, None)
        meta["last_dispatch"] = now_iso
        meta["dispatch_message"] = message
        meta["dispatch_results"] = details
        meta["dispatched_targets"] = [info["target"] for info in details if info.get("success")]
        meta["status"] = "dispatched" if success else "error"
        if success:
            dispatched_count += 1
    with MONITOR_LOCK:
        monitor_ref = MONITOR_STATE.get(monitor_id)
        if not monitor_ref:
            return
        monitor_ref["entries"] = existing_map
        monitor_ref["last_checked"] = now_iso
        monitor_ref["last_status"] = "ok"
        monitor_ref["last_error"] = ""
        monitor_ref["last_entry_count"] = len(entries)
        monitor_ref["last_new_entries"] = len(new_entries)
        monitor_ref["last_dispatch_count"] = dispatched_count
        monitor_ref["next_check_ts"] = time.time() + interval
        _save_monitors_locked()


def monitor_worker_loop() -> None:
    while True:
        time.sleep(MONITOR_POLL_INTERVAL)
        with MONITOR_LOCK:
            due_ids = []
            now_ts = time.time()
            for monitor_id, monitor in MONITOR_STATE.items():
                next_ts = monitor.get("next_check_ts") or 0
                interval = max(60, int(monitor.get("interval") or DEFAULT_MONITOR_INTERVAL))
                if now_ts >= next_ts:
                    monitor["next_check_ts"] = now_ts + interval
                    due_ids.append(monitor_id)
        for monitor_id in due_ids:
            try:
                process_monitor(monitor_id)
            except Exception as exc:
                log(f"Monitor {monitor_id} processing error: {exc}")


def start_monitor_worker() -> None:
    global MONITOR_THREAD
    with MONITOR_LOCK:
        already_running = MONITOR_THREAD and MONITOR_THREAD.is_alive()
    if already_running:
        return
    load_monitors_state()
    thread = threading.Thread(target=monitor_worker_loop, name="monitor-worker", daemon=True)
    thread.start()
    with MONITOR_LOCK:
        MONITOR_THREAD = thread
