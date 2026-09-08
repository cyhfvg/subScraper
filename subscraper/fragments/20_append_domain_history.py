"""Fragment 20_append_domain_history.py. Loaded into the main module namespace."""
def append_domain_history(domain: str, entry: Dict[str, Any]) -> None:
    """Append an entry to domain history in SQLite database."""
    if not domain or not entry:
        return
    try:
        db = get_db()
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        timestamp = entry.get("ts", now)
        source = entry.get("source", "system")
        text = entry.get("text", "")
        
        cursor.execute(
            """INSERT INTO history (domain, timestamp, source, text, created_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (domain, timestamp, source, text, now)
        )
        db.commit()
    except Exception as exc:
        log(f"Failed to write history for {domain}: {exc}")


def load_domain_history(domain: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Load domain history from SQLite database.
    
    Args:
        domain: The domain to load history for
        limit: Maximum number of recent entries to return (None = all entries)
               When limit is specified, returns the most recent entries.
    
    Returns:
        List of history events in chronological order (oldest first)
    
    Note:
        Uses ORDER BY timestamp DESC, id DESC to ensure consistent ordering
        when multiple entries have the same timestamp. The id DESC ensures
        that within the same timestamp, newer entries (higher id) come first
        in the DESC sort, maintaining insertion order.
    """
    db = get_db()
    cursor = db.cursor()
    
    if limit is not None and limit > 0:
        # Efficiently get the last N entries using a subquery
        # Inner query: get last N entries ordered DESC (including id for proper ordering)
        # Outer query: re-order them ASC for chronological display
        cursor.execute(
            """SELECT timestamp, source, text FROM (
                   SELECT id, timestamp, source, text FROM history 
                   WHERE domain = ? 
                   ORDER BY timestamp DESC, id DESC
                   LIMIT ?
               ) ORDER BY timestamp ASC, id ASC""",
            (domain, limit)
        )
        rows = cursor.fetchall()
    else:
        # Load all entries (for backward compatibility, though not recommended for large datasets)
        cursor.execute(
            """SELECT timestamp, source, text FROM history 
               WHERE domain = ? 
               ORDER BY timestamp ASC""",
            (domain,)
        )
        rows = cursor.fetchall()
    
    events = []
    for row in rows:
        events.append({
            "ts": row[0],
            "source": row[1],
            "text": row[2]
        })
    
    return events


def ensure_job_control(domain: Optional[str]) -> Optional[JobControl]:
    if not domain:
        return None
    with JOB_CONTROL_LOCK:
        ctrl = JOB_CONTROLS.get(domain)
        if ctrl is None:
            ctrl = JobControl()
            JOB_CONTROLS[domain] = ctrl
        return ctrl


def get_job_control(domain: Optional[str]) -> Optional[JobControl]:
    if not domain:
        return None
    with JOB_CONTROL_LOCK:
        return JOB_CONTROLS.get(domain)


def cleanup_job_control(domain: Optional[str]) -> None:
    if not domain:
        return
    with JOB_CONTROL_LOCK:
        JOB_CONTROLS.pop(domain, None)
        ACTIVE_PAUSED_JOBS.discard(domain)


def job_pause_point(domain: Optional[str]) -> None:
    """流水线检查点: 处理暂停等待, 并在取消时抛出 JobCancelled.

    Args:
        domain: 当前 Job 域名, 空值直接返回.
    Returns:
        None.
    Raises:
        JobCancelled: 用户删除/取消了该 Job.
    Example:
        job_pause_point("example.com")
    """
    if not domain:
        return
    ctrl = get_job_control(domain)
    if not ctrl:
        return
    if ctrl.is_cancel_requested():
        raise JobCancelled(domain)
    if not ctrl.is_pause_requested():
        return
    should_notify = False
    with JOB_CONTROL_LOCK:
        if domain not in ACTIVE_PAUSED_JOBS:
            ACTIVE_PAUSED_JOBS.add(domain)
            should_notify = True
    if should_notify:
        job_set_status(domain, "paused", "Job paused by user.")
        job_log_append(domain, "Job paused by user.", "scheduler")
    ctrl.wait_until_resumed()
    if ctrl.is_cancel_requested():
        raise JobCancelled(domain)
    removed = False
    with JOB_CONTROL_LOCK:
        if domain in ACTIVE_PAUSED_JOBS:
            ACTIVE_PAUSED_JOBS.remove(domain)
            removed = True
    if removed:
        job_set_status(domain, "running", "Job resumed.")
        job_log_append(domain, "Job resumed by user.", "scheduler")


def job_sleep(job_domain: Optional[str], seconds: float, chunk: float = 1.0) -> None:
    if seconds <= 0:
        return
    end_time = time.time() + seconds
    while True:
        remaining = end_time - time.time()
        if remaining <= 0:
            break
        job_pause_point(job_domain)
        time.sleep(min(chunk, max(0.1, remaining)))



def snapshot_running_jobs() -> List[Dict[str, Any]]:
    with JOB_LOCK:
        results = []
        
        # Add running jobs
        for domain, job in RUNNING_JOBS.items():
            steps = {name: dict(data) for name, data in (job.get("steps") or {}).items()}
            thread_alive = bool(job.get("thread") and job["thread"].is_alive())
            logs = [dict(entry) for entry in job.get("logs", [])]
            results.append({
                "job_id": domain,
                "domain": domain,
                "started": job.get("started"),
                "queued_at": job.get("queued_at"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
                "status": job.get("status", "running"),
                "message": job.get("message", ""),
                "progress": job.get("progress", 0),
                "last_update": job.get("last_update"),
                "thread_alive": thread_alive,
                "steps": steps,
                "logs": logs,
                "completed_at": None,
            })
        
        # Add completed jobs
        for job_key, job in COMPLETED_JOBS.items():
            steps = {name: dict(data) for name, data in (job.get("steps") or {}).items()}
            logs = [dict(entry) for entry in job.get("logs", [])]
            results.append({
                "job_id": job_key,
                "domain": job.get("domain"),
                "started": job.get("started"),
                "queued_at": job.get("queued_at"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
                "status": job.get("status", "completed"),
                "message": job.get("message", ""),
                "progress": job.get("progress", 100),
                "last_update": job.get("last_update"),
                "thread_alive": False,
                "steps": steps,
                "logs": logs,
                "completed_at": job.get("completed_at"),
            })
        
        return results


def job_queue_snapshot() -> List[Dict[str, Any]]:
    with JOB_LOCK:
        snapshot = []
        for position, domain in enumerate(JOB_QUEUE, start=1):
            job = RUNNING_JOBS.get(domain)
            if not job:
                continue
            snapshot.append({
                "domain": domain,
                "position": position,
                "queued_at": job.get("queued_at"),
                "wordlist": job.get("wordlist") or "",
                "skip_nikto": job.get("skip_nikto", False),
                "interval": job.get("interval", DEFAULT_INTERVAL),
            })
        return snapshot


def snapshot_workers() -> Dict[str, Any]:
    with JOB_LOCK:
        active_jobs = count_active_jobs_locked()
        queue_len = len(JOB_QUEUE)
    # Include all tools with their gate information if they have one
    tool_stats = {}
    for name in TOOLS.keys():
        if name in TOOL_GATES:
            # Tool has a gate, show active/limit
            tool_stats[name] = TOOL_GATES[name].snapshot()
        else:
            # Tool without gate, show as available but no concurrency limit
            tool_stats[name] = {
                "limit": None,
                "active": 0,
            }
    
    # Include timeout tracking statistics
    timeout_stats = {}
    with TIMEOUT_TRACKER_LOCK:
        for domain, tracker in TIMEOUT_TRACKER.items():
            timeout_stats[domain] = {
                "errors": tracker["errors"],
                "last_error_time": tracker["last_error_time"],
                "backoff_delay": tracker["backoff_delay"],
            }
    
    return {
        "job_slots": {
            "limit": MAX_RUNNING_JOBS,
            "active": active_jobs,
            "queue": queue_len,
            "dynamic_mode": DYNAMIC_MODE_ENABLED,
        },
        "tools": tool_stats,
        "rate_limiting": {
            "current_delay": GLOBAL_RATE_LIMIT_DELAY,
            "max_auto_backoff": MAX_AUTO_BACKOFF_DELAY,
            "timeout_tracker": timeout_stats,
        },
        "dynamic_mode": get_dynamic_mode_status(),
        "auto_backup": get_auto_backup_status(),
    }


def build_targets_csv(state: Dict[str, Any]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["domain", "subdomains", "http_entries", "nuclei_findings", "nikto_findings", "screenshots"])
    targets = state.get("targets", {})
    for domain, info in sorted(targets.items()):
        subs = info.get("subdomains", {})
        sub_keys = subs.keys()
        http_count = sum(1 for data in subs.values() if data.get("httpx"))
        nuclei_count = sum(len(data.get("nuclei") or []) for data in subs.values())
        nikto_count = sum(len(data.get("nikto") or []) for data in subs.values())
        screenshot_count = sum(1 for data in subs.values() if data.get("screenshot"))
        writer.writerow([domain, len(sub_keys), http_count, nuclei_count, nikto_count, screenshot_count])
    return output.getvalue().encode("utf-8")


def extract_finding_severity(finding: Dict[str, Any], is_nikto: bool = False) -> str:
    """Extract and normalize severity from a finding (nuclei or nikto)."""
    if is_nikto:
        # Nikto findings may use 'severity' or 'risk' field
        severity = (finding.get("severity") or finding.get("risk") or "INFO").upper()
    else:
        # Nuclei findings use 'severity' field
        severity = (finding.get("severity") or "INFO").upper()
    
    # Validate and return
    return severity if severity in SEVERITY_LEVELS else "INFO"


def get_max_severity(info: Dict[str, Any]) -> str:
    """Calculate the maximum severity for a domain based on nuclei and nikto findings."""
    max_severity = 'NONE'
    
    subs = info.get("subdomains", {})
    for sub_data in subs.values():
        # Check nuclei findings
        for finding in sub_data.get("nuclei", []):
            severity = extract_finding_severity(finding, is_nikto=False)
            if SEVERITY_LEVELS.index(severity) > SEVERITY_LEVELS.index(max_severity):
                max_severity = severity
        
        # Check nikto findings
        for finding in sub_data.get("nikto", []):
            severity = extract_finding_severity(finding, is_nikto=True)
            if SEVERITY_LEVELS.index(severity) > SEVERITY_LEVELS.index(max_severity):
                max_severity = severity
    
    return max_severity


def filter_domains_by_criteria(state: Dict[str, Any], filters: Dict[str, Any]) -> List[str]:
    """Filter domains based on report filter criteria."""
    targets = state.get("targets", {})
    filtered_domains = []
    
    for domain, info in targets.items():
        # Exact single-domain filter (per-report export)
        if filters.get("domain"):
            if domain != filters["domain"]:
                continue
        
        # Domain search filter
        if filters.get("domainSearch"):
            if filters["domainSearch"].lower() not in domain.lower():
                continue
        
        # Status filter (pending/complete)
        if filters.get("status", "all") != "all":
            is_pending = info.get("pending", False)
            if filters["status"] == "pending" and not is_pending:
                continue
            if filters["status"] == "complete" and is_pending:
                continue
        
        # Severity filter
        if filters.get("maxSeverity", "all") != "all":
            domain_severity = get_max_severity(info)
            filter_index = SEVERITY_LEVELS.index(filters["maxSeverity"])
            domain_index = SEVERITY_LEVELS.index(domain_severity)
            if domain_index < filter_index:
                continue
        
        # Has findings filter
        if filters.get("hasFindings", False):
            subs = info.get("subdomains", {})
            nuclei_count = sum(len(data.get("nuclei", [])) for data in subs.values())
            nikto_count = sum(len(data.get("nikto", [])) for data in subs.values())
            if nuclei_count == 0 and nikto_count == 0:
                continue
        
        # Has screenshots filter
        if filters.get("hasScreenshots", False):
            subs = info.get("subdomains", {})
            screenshot_count = sum(1 for data in subs.values() if data.get("screenshot"))
            if screenshot_count == 0:
                continue
        
        filtered_domains.append(domain)
    
    return filtered_domains


def _subdomain_matches_filters(subdomain: str, sub_data: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    """Return True if a subdomain passes subdomain-level export filters."""
    sub_search = filters.get("subSearch", "")
    if sub_search and sub_search.lower() not in subdomain.lower():
        return False
    
    status_codes = filters.get("statusCodes", "")
    if status_codes and status_codes != "all":
        allowed = set(c.strip() for c in status_codes.split(",") if c.strip())
        httpx = sub_data.get("httpx", {})
        raw_code = httpx.get("status_code")
        code = str(raw_code) if raw_code else "none"
        if allowed and code not in allowed:
            return False
    
    return True


def export_subdomains_txt(state: Dict[str, Any], filters: Dict[str, Any]) -> bytes:
    """Export subdomains as plain text, one per line, respecting filters."""
    filtered_domains = filter_domains_by_criteria(state, filters)
    targets = state.get("targets", {})
    
    subdomains = []
    for domain in filtered_domains:
        info = targets.get(domain, {})
        subs = info.get("subdomains", {})
        for sub, sub_data in sorted(subs.items()):
            if _subdomain_matches_filters(sub, sub_data, filters):
                subdomains.append(sub)
    
    # Remove duplicates and sort
    unique_subdomains = sorted(set(subdomains))
    return "\n".join(unique_subdomains).encode("utf-8")


def export_subdomains_csv(state: Dict[str, Any], filters: Dict[str, Any]) -> bytes:
    """Export subdomains as CSV with details, respecting filters."""
    filtered_domains = filter_domains_by_criteria(state, filters)
    targets = state.get("targets", {})
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["subdomain", "parent_domain", "status_code", "title", "server", "has_screenshot", "nuclei_findings", "nikto_findings", "sources"])
    
    for domain in sorted(filtered_domains):
        info = targets.get(domain, {})
        subs = info.get("subdomains", {})
        
        for subdomain in sorted(subs.keys()):
            sub_data = subs[subdomain]
            if not _subdomain_matches_filters(subdomain, sub_data, filters):
                continue
            httpx = sub_data.get("httpx") or {}
            status_code = httpx.get("status_code", "")
            title = httpx.get("title", "")
            server = httpx.get("webserver", "")
            has_screenshot = "Yes" if sub_data.get("screenshot") else "No"
            nuclei_count = len(sub_data.get("nuclei", []))
            nikto_count = len(sub_data.get("nikto", []))
            sources = ", ".join(sub_data.get("sources", []))
            
            writer.writerow([subdomain, domain, status_code, title, server, has_screenshot, nuclei_count, nikto_count, sources])
    
    return output.getvalue().encode("utf-8")


def pause_job(domain: str) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    with JOB_LOCK:
        job = RUNNING_JOBS.get(normalized)
        if not job:
            return False, f"No active job for {normalized}."
        thread = job.get("thread")
    if not thread or not thread.is_alive():
        return False, f"Job thread for {normalized} is not running."
    ctrl = ensure_job_control(normalized)
    if not ctrl.request_pause():
        return False, f"{normalized} is already paused."
    job_set_status(normalized, "pausing", "Pause requested; waiting for pipeline to acknowledge.")
    job_log_append(normalized, "Pause requested by user.", "scheduler")
    return True, f"{normalized} will pause momentarily."


def resume_job(domain: str) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    with JOB_LOCK:
        job = RUNNING_JOBS.get(normalized)
        if not job:
            return False, f"No active job for {normalized}."
        thread = job.get("thread")
    if not thread or not thread.is_alive():
        return False, f"Job thread for {normalized} is not running."
    ctrl = get_job_control(normalized)
    if not ctrl:
        return False, f"No control handle for {normalized}."
    if not ctrl.request_resume():
        return False, f"{normalized} is not paused."
    job_set_status(normalized, "running", "Job resumed.")
    job_log_append(normalized, "Job resumed by user.", "scheduler")
    return True, f"{normalized} has been resumed."


def delete_job(domain: str = "", job_id: str = "") -> Tuple[bool, str]:
    """删除排队中、运行中或已完成的 Job.

    Args:
        domain: 运行中/排队中任务的域名.
        job_id: 已完成任务的唯一键 (domain_timestamp); 也可传入域名.
    Returns:
        (success, message)
    Raises:
        无. 数据库异常被吞并并记入日志.
    Example:
        ok, msg = delete_job(domain="example.com")
        ok, msg = delete_job(job_id="example.com_1702901234.5")
    """
    job_id = (job_id or "").strip()
    normalized = (domain or "").strip().lower()
    if not normalized and job_id:
        if job_id in COMPLETED_JOBS:
            normalized = ""
        else:
            normalized = job_id.rsplit("_", 1)[0].lower() if "_" in job_id else job_id.lower()

    if job_id:
        removed_completed = False
        with JOB_LOCK:
            if job_id in COMPLETED_JOBS:
                COMPLETED_JOBS.pop(job_id, None)
                removed_completed = True
        if removed_completed:
            try:
                db = get_db()
                db.execute("DELETE FROM completed_jobs WHERE job_key = ?", (job_id,))
                db.commit()
            except Exception as exc:
                log(f"Failed to delete completed job {job_id}: {exc}", "error")
                return False, f"Failed to delete completed job {job_id}."
            log(f"Deleted completed job {job_id}")
            return True, f"Deleted completed job {job_id}."

    if not normalized:
        return False, "Domain or job_id is required."

    queued_removed = False
    running_cancel = False
    with JOB_LOCK:
        job = RUNNING_JOBS.get(normalized)
        if job and job.get("status") == "queued":
            try:
                JOB_QUEUE.remove(normalized)
            except ValueError:
                pass
            RUNNING_JOBS.pop(normalized, None)
            queued_removed = True
        elif job:
            running_cancel = True

    if queued_removed:
        cleanup_job_control(normalized)
        persist_active_jobs()
        log(f"Deleted queued job {normalized}")
        return True, f"Deleted queued job {normalized}."

    if running_cancel:
        ctrl = ensure_job_control(normalized)
        if not ctrl.request_cancel():
            RUNNING_JOBS.pop(normalized, None)
            cleanup_job_control(normalized)
            persist_active_jobs()
            return True, f"Removed job {normalized}."
        job_set_status(normalized, "cancelling", "Delete requested; stopping pipeline.")
        job_log_append(normalized, "Job deleted by user.", "scheduler")
        persist_active_jobs()
        log(f"Cancel requested for running job {normalized}")
        return True, f"{normalized} will be deleted shortly."

    return False, f"No job found for {normalized or job_id}."

