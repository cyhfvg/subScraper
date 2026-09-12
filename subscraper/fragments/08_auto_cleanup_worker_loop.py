"""Fragment 08_auto_cleanup_worker_loop.py. Loaded into the main module namespace."""
def auto_cleanup_worker_loop() -> None:
    """Background worker that performs automatic cleanup on a schedule."""
    global LAST_CLEANUP_TIME
    
    log("Auto-cleanup worker started.")
    
    # Set initial cleanup time to now to avoid immediate cleanup on start
    LAST_CLEANUP_TIME = time.time()
    
    while not CLEANUP_STOP_EVENT.is_set():
        try:
            if not AUTO_CLEANUP_ENABLED:
                # Wait with timeout so we can respond to stop event
                CLEANUP_STOP_EVENT.wait(timeout=60)
                continue
            
            current_time = time.time()
            time_since_cleanup = current_time - LAST_CLEANUP_TIME
            
            if time_since_cleanup >= CLEANUP_INTERVAL:
                log("⏰ Auto-cleanup triggered")
                stats = run_cleanup()
                LAST_CLEANUP_TIME = current_time
            
            # Sleep with timeout so we can respond to stop event
            CLEANUP_STOP_EVENT.wait(timeout=60)
        except Exception as exc:
            log(f"Error in auto-cleanup worker: {exc}")
            CLEANUP_STOP_EVENT.wait(timeout=60)
    
    log("Auto-cleanup worker stopped.")


def start_cleanup_worker() -> None:
    """Start the auto-cleanup worker thread."""
    global CLEANUP_THREAD
    
    with CLEANUP_LOCK:
        already_running = CLEANUP_THREAD and CLEANUP_THREAD.is_alive()
    
    if already_running:
        return
    
    # Clear stop event before starting
    CLEANUP_STOP_EVENT.clear()
    
    thread = threading.Thread(target=auto_cleanup_worker_loop, name="auto-cleanup", daemon=True)
    thread.start()
    
    with CLEANUP_LOCK:
        CLEANUP_THREAD = thread
    
    log("Auto-cleanup worker initialized.")


def stop_cleanup_worker() -> None:
    """Stop the auto-cleanup worker thread."""
    global CLEANUP_THREAD
    
    with CLEANUP_LOCK:
        if CLEANUP_THREAD and CLEANUP_THREAD.is_alive():
            # Signal thread to stop
            CLEANUP_STOP_EVENT.set()
            CLEANUP_THREAD = None
            log("Auto-cleanup worker stop signal sent.")


def get_cleanup_status() -> Dict[str, Any]:
    """Get current auto-cleanup status."""
    with CLEANUP_LOCK:
        next_cleanup_time = LAST_CLEANUP_TIME + CLEANUP_INTERVAL if AUTO_CLEANUP_ENABLED else None
        return {
            "enabled": AUTO_CLEANUP_ENABLED,
            "interval_seconds": CLEANUP_INTERVAL,
            "scan_results_retention_days": CLEANUP_SCAN_RESULTS_DAYS,
            "temp_files_retention_hours": CLEANUP_TEMP_FILES_HOURS,
            "last_cleanup_timestamp": LAST_CLEANUP_TIME,
            "next_cleanup_timestamp": next_cleanup_time,
            "next_cleanup": datetime.fromtimestamp(next_cleanup_time, tz=timezone.utc).isoformat() if next_cleanup_time else None,
            "worker_active": CLEANUP_THREAD and CLEANUP_THREAD.is_alive() if CLEANUP_THREAD else False,
        }


def save_config(cfg: Dict[str, Any]) -> None:
    """Save configuration to SQLite database with proper error handling."""
    ensure_dirs()
    
    try:
        db = get_db()  # get_db() uses DB_LOCK internally
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        # Temporarily set isolation_level to enable proper transaction handling
        # Note: Connection is normally in autocommit mode (isolation_level=None)
        # We need to switch to manual transaction mode for atomic save
        old_isolation = db.isolation_level
        try:
            # Switch to manual transaction mode (empty string enables manual control)
            db.isolation_level = ''
            
            # Now start an explicit transaction with IMMEDIATE lock
            # This provides exclusive write access and prevents concurrent modifications
            cursor.execute("BEGIN IMMEDIATE")
            try:
                for key, value in cfg.items():
                    cursor.execute(
                        "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, ?)",
                        (key, json.dumps(value), now)
                    )
                
                # Commit the transaction using connection-level method
                db.commit()
            except Exception as e:
                # Rollback on any error using connection-level method
                db.rollback()
                log(f"Error saving config, transaction rolled back: {e}")
                raise
        finally:
            # Restore original isolation level
            db.isolation_level = old_isolation
        
        # Update in-memory config after successful save
        with CONFIG_LOCK:
            CONFIG.clear()
            CONFIG.update(cfg)
        
        # Apply concurrency limits
        # Wrap in try-except to prevent config save from failing if applying limits fails
        try:
            apply_concurrency_limits(cfg)
        except Exception as apply_err:
            log(f"Warning: Config saved successfully but failed to apply concurrency limits: {apply_err}")
            # Don't re-raise - config was saved successfully, we just couldn't apply the runtime changes
    except Exception as e:
        log(f"Failed to save configuration: {e}")
        raise


def _migrate_tool_worker_settings(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Configs written before per-tool worker counts were introduced pinned every
    tool to 1 slot, which was the old default rather than a deliberate choice.
    Those are switched to "inherit", so the single Workers-per-tool setting
    takes effect. Anything the user actually raised is left alone.
    """
    if cfg.get("_tool_workers_migrated"):
        return cfg
    fields = list(TOOL_PARALLEL_FIELDS.values())
    values = [cfg.get(field) for field in fields]
    changed = bool(values) and all(value == 1 for value in values)
    if changed:
        for field in fields:
            cfg[field] = 0
        log(f"Tool worker settings were all at the old default of 1; they now follow "
            f"'Workers per tool' ({default_tool_workers(cfg)}).")
    cfg["_tool_workers_migrated"] = True
    # Only persist when something actually moved, so simply reading the config
    # never rewrites it.
    if changed:
        save_config(cfg)
    return cfg


def load_config() -> Dict[str, Any]:
    """Load configuration from SQLite database."""
    ensure_dirs()
    cfg = default_config()
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT key, value FROM config")
    rows = cursor.fetchall()
    
    if rows:
        for row in rows:
            key = row[0]
            try:
                value = json.loads(row[1])
                if key in cfg:
                    cfg[key] = value
            except json.JSONDecodeError:
                pass
    else:
        # No config in database, save defaults
        save_config(cfg)
    cfg["tool_flag_templates"] = _normalize_tool_flag_templates(cfg.get("tool_flag_templates"))
    cfg = _migrate_tool_worker_settings(cfg)
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(cfg)
    
    # Apply concurrency limits
    # Wrap in try-except to prevent config load from failing if applying limits fails
    try:
        apply_concurrency_limits(cfg)
    except Exception as apply_err:
        log(f"Warning: Config loaded successfully but failed to apply concurrency limits: {apply_err}")
        # Don't re-raise - config was loaded successfully, we just couldn't apply the runtime changes
    
    return dict(CONFIG)


def get_config() -> Dict[str, Any]:
    with CONFIG_LOCK:
        if CONFIG:
            return dict(CONFIG)
    return load_config()


def bool_from_value(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        val = value.strip().lower()
        return val in {"1", "true", "yes", "on"}
    return default


def _sanitize_domain_input(value: str) -> str:
    """规范化用户输入, 保留 IPv4 CIDR 前缀长度.

    Args:
        value: 域名 / IP / CIDR / URL.

    Returns:
        str: 规范化目标; 无法识别时返回空串.

    Raises:
        无.

    调用示例:
        _sanitize_domain_input("https://10.0.0.8:8443/")  # "10.0.0.8"
        _sanitize_domain_input("10.1.0.0/24")             # "10.1.0.0/24"
    """
    parsed = parse_scan_target(value)
    return parsed.normalized if parsed else ""


def _parse_multiple_domains(value: str) -> List[str]:
    """
    Parse multiple domain inputs separated by commas or newlines.
    Returns a deduplicated list of lowercase domain strings.
    
    Examples:
      "example.com, test.com"
      "*.example.com\n*.test.com"
      "*-*-*-*.tangos.nl, *.adsl.xs4all.be"
    """
    if not value:
        return []
    
    # Split by both newlines and commas
    raw_domains = []
    for line in value.split('\n'):
        # For each line, split by commas
        for domain in line.split(','):
            stripped = domain.strip()
            if stripped:
                raw_domains.append(stripped)
    
    # Deduplicate while preserving order (normalize to lowercase)
    seen = set()
    result = []
    for domain in raw_domains:
        domain_lower = domain.lower()
        if domain_lower and domain_lower not in seen:
            seen.add(domain_lower)
            result.append(domain_lower)  # Append normalized version
    
    return result


def _normalize_tld_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = re.split(r"[,\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]
    result: List[str] = []
    seen: set = set()
    for item in raw_items:
        text = str(item or "").strip().lower().lstrip(".")
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _normalize_resolver_list(value: Any) -> List[str]:
    """
    解析 DNS resolver 列表. 接受逗号/空白/换行分隔的字符串或 list.

    Args:
        value: 原始配置值.

    Returns:
        List[str]: 去重后的 resolver, 形如 10.0.0.1 或 10.0.0.1:53.

    Raises:
        无.

    调用示例:
        _normalize_resolver_list("10.0.0.1, 10.0.0.2:53")
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = re.split(r"[,;\s]+", str(value))
    result: List[str] = []
    seen: set = set()
    for item in raw_items:
        text = str(item or "").strip()
        if not text or text.startswith("#"):
            continue
        if any(ch in text for ch in " /\\\"'<>"):
            continue
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def write_resolvers_file(resolvers: List[str]) -> Path:
    """
    把 resolver 列表写到 recon_data/resolvers.txt, 供 dnsx -r 使用.

    Args:
        resolvers: 已规范化的 DNS 地址.

    Returns:
        Path: resolvers.txt 路径.

    Raises:
        OSError: 写文件失败时由调用方处理.

    调用示例:
        write_resolvers_file(["10.0.0.1"])
    """
    ensure_dirs()
    RESOLVERS_FILE.write_text("\n".join(resolvers) + "\n", encoding="utf-8")
    return RESOLVERS_FILE


def resolve_wordlist_path(raw: Optional[str]) -> Optional[str]:
    """
    解析 wordlist 路径. 相对路径依次试 WORDLISTS_DIR、DATA_DIR、cwd.

    Args:
        raw: 用户填写的路径.

    Returns:
        Optional[str]: 存在则返回绝对路径, 否则返回原字符串 (调用方记录 not found).

    Raises:
        无.

    调用示例:
        resolve_wordlist_path("subdomains.txt")
    """
    text = str(raw or "").strip()
    if not text:
        return None
    candidates = [Path(text)]
    p = Path(text)
    if not p.is_absolute():
        candidates.extend([WORDLISTS_DIR / p.name, WORDLISTS_DIR / p, DATA_DIR / p, Path.cwd() / p])
    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate.resolve())
        except OSError:
            continue
    return text


def save_uploaded_wordlist(filename: str, content: str) -> Tuple[bool, str, str]:
    """
    把上传的 wordlist 写到 recon_data/wordlists/.

    Args:
        filename: 原始文件名, 只保留 basename.
        content: 文本内容.

    Returns:
        Tuple[bool, str, str]: (成功, 消息, 保存后的绝对路径).

    Raises:
        无. 失败返回 False.

    调用示例:
        save_uploaded_wordlist("subs.txt", "www\\napi\\n")
    """
    name = Path(filename or "wordlist.txt").name
    if not re.match(r"^[A-Za-z0-9._-]{1,128}$", name) or name.startswith("."):
        return False, "Invalid filename. Use letters, digits, dot, underscore, hyphen.", ""
    if not re.search(r"\.(txt|lst|wl)$", name, re.IGNORECASE):
        name = name + ".txt"
    encoded = content.encode("utf-8")
    if len(encoded) > 20 * 1024 * 1024:
        return False, "Wordlist too large (max 20MB).", ""
    ensure_dirs()
    dest = WORDLISTS_DIR / name
    dest.write_bytes(encoded)
    return True, f"Saved {name}.", str(dest.resolve())
