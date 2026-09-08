"""Fragment 21_skip_job_step.py. Loaded into the main module namespace."""
def skip_job_step(domain: str, step: str) -> Tuple[bool, str]:
    """
    Skip a specific pipeline step for a job.
    Marks the step as done to prevent it from running.
    """
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    if not step:
        return False, "Step name is required."
    
    # Validate step name
    if step not in PIPELINE_STEPS:
        return False, f"Invalid step name: {step}. Valid steps: {', '.join(PIPELINE_STEPS)}"
    
    with JOB_LOCK:
        job = RUNNING_JOBS.get(normalized)
        if not job:
            return False, f"No active job for {normalized}."
    
    # Load state and mark step as done
    state = load_state()
    target = state.get("targets", {}).get(normalized)
    
    if not target:
        return False, f"No target data found for {normalized}."
    
    flags = target.get("flags", {})
    flag_name = f"{step}_done"
    
    # Check if already done
    if flags.get(flag_name):
        return False, f"Step '{step}' is already marked as done for {normalized}."
    
    # Mark as done
    flags[flag_name] = True
    target["flags"] = flags
    save_state(state)
    
    # Update job step status
    job_step_update(normalized, step, status="skipped", message="Skipped by user", progress=0)
    job_log_append(normalized, f"Step '{step}' skipped by user.", "scheduler")
    
    return True, f"Step '{step}' has been skipped for {normalized}."


def cancel_all_jobs() -> Tuple[bool, str, List[Dict[str, str]]]:
    """
    Cancel all running jobs by pausing them.
    Returns list of results for each job.
    """
    with JOB_LOCK:
        running_domains = [
            domain for domain, job in RUNNING_JOBS.items()
            if job.get("status") == "running" and job.get("thread") and job.get("thread").is_alive()
        ]
    
    if not running_domains:
        return True, "No running jobs to cancel.", []
    
    results = []
    cancelled_count = 0
    
    for domain in running_domains:
        success, message = pause_job(domain)
        results.append({
            "domain": domain,
            "success": success,
            "message": message,
        })
        if success:
            cancelled_count += 1
    
    if cancelled_count == 0:
        return False, "Failed to cancel any jobs.", results
    elif cancelled_count < len(running_domains):
        return True, f"Cancelled {cancelled_count} of {len(running_domains)} running jobs.", results
    else:
        return True, f"Successfully cancelled all {cancelled_count} running jobs.", results

    if not ctrl:
        return False, f"{normalized} is not currently paused."
    if not ctrl.request_resume():
        return False, f"{normalized} is not paused."
    job_set_status(normalized, "running", "Resume requested by user.")
    job_log_append(normalized, "Resume requested by user.", "scheduler")
    return True, f"{normalized} resumed."


def resume_all_paused_jobs() -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Resume all paused jobs at once."""
    with JOB_LOCK:
        paused_domains = []
        for domain, job in RUNNING_JOBS.items():
            status = job.get("status", "")
            if status in ("paused", "pausing"):
                thread = job.get("thread")
                if thread and thread.is_alive():
                    paused_domains.append(domain)
    
    if not paused_domains:
        return False, "No paused jobs found.", []
    
    results = []
    resumed_count = 0
    for domain in paused_domains:
        success, message = resume_job(domain)
        results.append({
            "domain": domain,
            "success": success,
            "message": message,
        })
        if success:
            resumed_count += 1
    
    if resumed_count == 0:
        return False, "Failed to resume any jobs.", results
    elif resumed_count < len(paused_domains):
        return True, f"Resumed {resumed_count} of {len(paused_domains)} paused jobs.", results
    else:
        return True, f"Resumed all {resumed_count} paused jobs.", results


def resume_target_scan(domain: str, wordlist: Optional[str] = None,
                       skip_nikto: Optional[bool] = None) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."
    cfg = get_config()
    state = load_state()
    target = state.get("targets", {}).get(normalized)
    if not target:
        return False, f"No stored reconnaissance data for {normalized}."
    if not target_has_pending_work(target, cfg):
        return False, f"{normalized} already completed all steps."
    options = target.get("options") or {}
    if skip_nikto is None:
        if "skip_nikto" in options:
            skip_flag = bool(options.get("skip_nikto"))
        else:
            skip_flag = bool(cfg.get("skip_nikto_by_default", False))
    else:
        skip_flag = bool(skip_nikto)
    wordlist_val = None
    if wordlist:
        cleaned = str(wordlist).strip()
        if cleaned:
            wordlist_val = cleaned
    return start_pipeline_job(normalized, wordlist_val, skip_flag, None)


# Registrable-domain (eTLD+1) extraction. Not a full public-suffix list, just
# the common multi-label suffixes so hosts like foo.google.co.uk group under
# google.co.uk instead of the wrong co.uk.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.co", "com.tr", "com.sg", "com.hk", "com.cn",
    "co.in", "co.za", "co.il", "co.th", "com.tw", "com.ua", "com.ph",
}

# Valid domain / FQDN (optionally leading "*."), used to filter import tokens.
_IMPORT_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def registrable_root(host: str) -> str:
    """Return the eTLD+1 (registrable domain) for a host, best-effort."""
    host = (host or "").strip().lower().strip(".")
    while host.startswith("*."):
        host = host[2:]
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def parse_domain_import(content: str) -> List[str]:
    """
    Extract FQDNs from imported text. Supports:
      - Plain lists (newline / comma separated)
      - CSV / JSON (quoted values)
      - Google bug-hunters .asciipb protobuf-text (fqdn: "host" entries)
    Comment lines (# / //) and non-domain tokens (e.g. TIER0, {}) are ignored.
    """
    if not content:
        return []
    candidates: List[str] = []
    # Quoted values cover asciipb `fqdn: "..."`, JSON and CSV.
    candidates.extend(re.findall(r'"([^"]+)"', content))
    # Bare tokens cover plain/comma lists.
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        for tok in re.split(r"[\s,]+", line):
            tok = tok.strip().strip('",:{}')
            if tok:
                candidates.append(tok)

    hosts: List[str] = []
    seen: set = set()
    for cand in candidates:
        cleaned = _sanitize_domain_input(cand)
        if not cleaned or cleaned in seen:
            continue
        if _IMPORT_DOMAIN_RE.match(cleaned):
            seen.add(cleaned)
            hosts.append(cleaned)
    return hosts


# Enumerator flags pre-marked done for imported targets so the pipeline skips
# subdomain discovery and jumps straight to downstream (dnsx/httpx/screenshots).
_IMPORT_SKIP_ENUM_FLAGS = [
    "amass_done", "subfinder_done", "assetfinder_done", "findomain_done",
    "sublist3r_done", "crtsh_done", "github_subdomains_done",
]


def import_domains_and_run(content: str, skip_nikto: bool,
                           interval: Optional[int]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Parse an imported domain list, add each host under its registrable root,
    and dispatch a pipeline job per root that skips enumeration and runs the
    downstream tooling (dnsx/httpx/screenshots/nuclei) on the imported hosts.
    """
    hosts = parse_domain_import(content)
    if not hosts:
        return False, "No valid domains found in the import.", {}

    groups: Dict[str, List[str]] = {}
    for host in hosts:
        root = registrable_root(host)
        if not root:
            continue
        bucket = groups.setdefault(root, [])
        if host not in bucket:
            bucket.append(host)

    state = load_state()
    for root, subs in groups.items():
        ensure_target_state(state, root)
        add_subdomains_to_state(state, root, subs, "import")
        flags = ensure_target_state(state, root)["flags"]
        for flag_key in _IMPORT_SKIP_ENUM_FLAGS:
            flags[flag_key] = True
    save_state(state)

    dispatched: List[str] = []
    failures: List[str] = []
    for root in groups:
        ok, msg = start_pipeline_job(root, None, skip_nikto, interval)
        if ok:
            dispatched.append(root)
        else:
            failures.append(msg)

    summary = (
        f"Imported {len(hosts)} host(s) across {len(groups)} domain(s); "
        f"dispatched {len(dispatched)} job(s) (screenshots + tooling)."
    )
    if failures:
        summary += " " + " ".join(failures)
    return bool(dispatched), summary, {
        "hosts": len(hosts),
        "domains": len(groups),
        "dispatched": dispatched,
    }


def start_targets_from_input(domain_input: str, wordlist: Optional[str],
                             skip_nikto: bool, interval: Optional[int]) -> Tuple[bool, str, List[Dict[str, Any]]]:
    cfg = get_config()
    cleaned = _sanitize_domain_input(domain_input)
    requested_any_tld = bool(cleaned.endswith(".*"))
    targets = expand_wildcard_targets(domain_input, cfg)
    if not targets:
        if requested_any_tld:
            return False, "Wildcard TLD requested but no TLDs are configured. Update wildcard TLDs in Settings.", []
        return False, "Domain is required.", []
    details: List[Dict[str, Any]] = []
    success_any = False
    for target in targets:
        success, message = start_pipeline_job(target, wordlist, skip_nikto, interval)
        if success:
            success_any = True
        details.append({
            "target": target,
            "success": success,
            "message": message,
        })
    if len(details) == 1:
        result = details[0]
        return result["success"], result["message"], details
    summary_parts: List[str] = []
    dispatched = [entry["target"] for entry in details if entry["success"]]
    if dispatched:
        summary_parts.append(f"Dispatched {len(dispatched)} job(s): {', '.join(dispatched)}.")
    failures = [entry["message"] for entry in details if not entry["success"]]
    if failures:
        summary_parts.append(" ".join(failures))
    if not summary_parts:
        summary_parts.append("No jobs were dispatched.")
    return success_any, " ".join(summary_parts).strip(), details


def start_pipeline_job(domain: str, wordlist: Optional[str], skip_nikto: bool, interval: Optional[int]) -> Tuple[bool, str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return False, "Domain is required."

    config = get_config()
    interval_val = max(5, interval or config.get("default_interval", DEFAULT_INTERVAL))
    default_wordlist = config.get("default_wordlist") or ""
    if wordlist is None or (isinstance(wordlist, str) and not wordlist.strip()):
        wordlist_path = default_wordlist.strip()
    else:
        wordlist_path = str(wordlist).strip()

    with JOB_LOCK:
        if normalized in RUNNING_JOBS:
            existing_status = RUNNING_JOBS[normalized].get('status', 'unknown')
            return True, f"A job for {normalized} is already {existing_status}. Continuing with existing scan."
        now = datetime.now(timezone.utc).isoformat()
        job_record = {
            "domain": normalized,
            "thread": None,
            "started": None,
            "queued_at": now,
            "wordlist": wordlist_path,
            "skip_nikto": skip_nikto,
            "interval": interval_val,
            "status": "queued",
            "message": "Waiting for a free slot.",
            "steps": init_job_steps(skip_nikto),
            "progress": 0,
            "last_update": now,
            "logs": [],
        }
        RUNNING_JOBS[normalized] = job_record
        ensure_job_control(normalized)
        if count_active_jobs_locked() < MAX_RUNNING_JOBS:
            start_now = True
        else:
            JOB_QUEUE.append(normalized)
            start_now = False

    if start_now:
        _start_job_thread(job_record)
        persist_active_jobs()
        return True, f"Recon started for {normalized}."

    job_log_append(normalized, "Queued for execution.", "scheduler")
    persist_active_jobs()
    return True, f"{normalized} queued; it will start when a worker is free."
