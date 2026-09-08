"""Fragment 19_run_pipeline.py. Loaded into the main module namespace."""
def run_pipeline(
    domain: str,
    wordlist: Optional[str],
    skip_nikto: bool = False,
    interval: int = DEFAULT_INTERVAL,
    job_domain: Optional[str] = None,
) -> None:
    ensure_dirs()
    config = get_config()
    if not wordlist:
        default_wordlist = config.get("default_wordlist") or ""
        wordlist = default_wordlist or None

    global HTML_REFRESH_SECONDS
    HTML_REFRESH_SECONDS = max(5, interval)

    def update_step(step_name: str, status: Optional[str] = None,
                    message: Optional[str] = None, progress: Optional[int] = None) -> None:
        job_step_update(job_domain, step_name, status=status, message=message, progress=progress)

    state = load_state()
    tgt = ensure_target_state(state, domain)
    flags = tgt["flags"]
    options = tgt.setdefault("options", {})
    if options.get("skip_nikto") != skip_nikto:
        options["skip_nikto"] = skip_nikto
        save_state(state)

    enumerators_done_event = threading.Event()
    downstream_started = threading.Event()
    downstream_thread_holder: Dict[str, threading.Thread] = {}
    seen_cache = {
        "amass": set(),
        "subfinder": set(),
        "assetfinder": set(),
        "findomain": set(),
        "sublist3r": set(),
        "crtsh": set(),
        "github-subdomains": set(),
    }

    def start_downstream_if_ready() -> None:
        if downstream_started.is_set():
            return
        current_state = load_state()
        sub_count = len(ensure_target_state(current_state, domain)["subdomains"])
        if sub_count == 0 and not enumerators_done_event.is_set():
            return
        downstream_started.set()
        t = threading.Thread(
            target=run_downstream_pipeline,
            args=(domain, wordlist, config, skip_nikto, interval, job_domain, enumerators_done_event),
            daemon=True,
        )
        downstream_thread_holder["thread"] = t
        t.start()

    def flush_loop() -> None:
        while not enumerators_done_event.is_set():
            harvest_enumerator_outputs(domain, config, seen_cache, job_domain)
            start_downstream_if_ready()
            job_sleep(job_domain, 30)
        harvest_enumerator_outputs(domain, config, seen_cache, job_domain)
        start_downstream_if_ready()

    flush_thread = threading.Thread(target=flush_loop, daemon=True)
    flush_thread.start()

    # ---------- Parallel Subdomain Enumerators ----------
    subdomain_input = is_subdomain_input(domain)
    if subdomain_input and not flags.get("amass_done"):
        log(f"Detected subdomain input ({domain}); seeding pipeline with that host.")
        add_subdomains_to_state(state, domain, [domain], "manual-input")
        flags["amass_done"] = True
        flags["subfinder_done"] = True
        flags["assetfinder_done"] = True
        save_state(state)
        start_downstream_if_ready()

    if subdomain_input:
        update_step("amass", status="skipped", message="Input is a subdomain; Amass skipped.", progress=0)
        update_step("subfinder", status="skipped", message="Input is a subdomain; Subfinder skipped.", progress=0)
        update_step("assetfinder", status="skipped", message="Input is a subdomain; Assetfinder skipped.", progress=0)
        update_step("crtsh", status="skipped", message="Input is a subdomain; crt.sh skipped.", progress=0)
        update_step("github-subdomains", status="skipped", message="Input is a subdomain; GitHub subdomains skipped.", progress=0)
    else:
        enumerator_specs = []
        enable_subfinder = config.get("enable_subfinder", True)
        enable_assetfinder = config.get("enable_assetfinder", True)
        enable_findomain = config.get("enable_findomain", True)
        enable_sublist3r = config.get("enable_sublist3r", True)
        enable_crtsh = config.get("enable_crtsh", True)
        enable_github_subdomains = config.get("enable_github_subdomains", True)

        def maybe_add_enum(step_name: str, flag_key: str, desc: str, func, enabled: bool = True):
            if not enabled:
                update_step(step_name, status="skipped", message=f"{desc} disabled in settings.", progress=0)
                return
            if flags.get(flag_key):
                update_step(step_name, status="skipped", message=f"{desc} already completed.", progress=0)
                return
            enumerator_specs.append((step_name, flag_key, desc, func))

        if config.get("enable_amass", True):
            maybe_add_enum(
                "amass",
                "amass_done",
                "Amass",
                lambda: amass_collect_subdomains(domain, config=config, job_domain=job_domain),
            )
        else:
            update_step("amass", status="skipped", message="Amass disabled in settings.", progress=0)

        maybe_add_enum(
            "subfinder",
            "subfinder_done",
            "Subfinder",
            lambda: subfinder_enum(domain, config, job_domain=job_domain),
            enable_subfinder,
        )
        maybe_add_enum(
            "assetfinder",
            "assetfinder_done",
            "Assetfinder",
            lambda: assetfinder_enum(domain, config, job_domain=job_domain),
            enable_assetfinder,
        )
        maybe_add_enum(
            "findomain",
            "findomain_done",
            "Findomain",
            lambda: findomain_enum(domain, config, job_domain=job_domain),
            enable_findomain,
        )
        maybe_add_enum(
            "sublist3r",
            "sublist3r_done",
            "Sublist3r",
            lambda: sublist3r_enum(domain, job_domain=job_domain),
            enable_sublist3r,
        )
        maybe_add_enum(
            "crtsh",
            "crtsh_done",
            "crt.sh",
            lambda: crtsh_enum(domain, job_domain=job_domain),
            enable_crtsh,
        )
        maybe_add_enum(
            "github-subdomains",
            "github_subdomains_done",
            "GitHub Subdomains",
            lambda: github_subdomains_enum(domain, job_domain=job_domain),
            enable_github_subdomains,
        )

        if enumerator_specs:
            enum_results: Dict[str, Optional[List[str]]] = {}
            enum_errors: Dict[str, str] = {}
            lock = threading.Lock()

            def enum_worker(name: str, func) -> None:
                try:
                    # Wait for tool slot if gate exists
                    if name in TOOL_GATES:
                        job_log_append(job_domain, f"Waiting for {name} slot...", "scheduler")
                        with TOOL_GATES[name]:
                            job_log_append(job_domain, f"{name} slot acquired.", "scheduler")
                            subs = func() or []
                    else:
                        subs = func() or []
                    with lock:
                        enum_results[name] = subs
                except Exception as exc:
                    log(f"{name} enumeration failed: {exc}")
                    job_log_append(job_domain, f"{name} failed: {exc}", name)
                    with lock:
                        enum_results[name] = None
                        enum_errors[name] = str(exc)

            threads = []
            for step_name, _, desc, func in enumerator_specs:
                update_step(step_name, status="running", message=f"{desc} in progress…", progress=40)
                t = threading.Thread(target=enum_worker, args=(step_name, func), daemon=True)
                threads.append((step_name, t))
                t.start()

            for _, t in threads:
                t.join()

            for step_name, flag_key, desc, _ in enumerator_specs:
                subs = enum_results.get(step_name)
                if subs is None:
                    update_step(step_name, status="error", message=f"{desc} failed: {enum_errors.get(step_name, 'Unknown error')}", progress=100)
                    continue
                current_state = load_state()
                add_subdomains_to_state(current_state, domain, subs, step_name)
                ensure_target_state(current_state, domain)["flags"][flag_key] = True
                save_state(current_state)
                job_log_append(job_domain, f"{desc} identified {len(subs)} subdomains.", step_name)
                update_step(step_name, status="completed", message=f"{desc} found {len(subs)} subdomains.", progress=100)
                start_downstream_if_ready()

    enumerators_done_event.set()
    flush_thread.join()
    start_downstream_if_ready()
    downstream_thread = downstream_thread_holder.get("thread")
    if downstream_thread:
        downstream_thread.join()
    else:
        run_downstream_pipeline(domain, wordlist, config, skip_nikto, interval, job_domain, enumerators_done_event)


# ================== JOB SCHEDULER ==================

def count_active_jobs_locked() -> int:
    return sum(1 for job in RUNNING_JOBS.values()
               if job.get("thread") and job["thread"].is_alive())


def _start_job_thread(job: Dict[str, Any]) -> None:
    domain = job["domain"]

    def runner():
        wordlist_path = job.get("wordlist") or None
        skip_nikto = job.get("skip_nikto", False)
        interval_val = job.get("interval", DEFAULT_INTERVAL)
        cancelled = False
        try:
            job_set_status(domain, "running", "Recon started.")
            run_pipeline(
                domain,
                wordlist_path,
                skip_nikto=skip_nikto,
                interval=interval_val,
                job_domain=domain,
            )
            with JOB_LOCK:
                job_record = RUNNING_JOBS.get(domain)
                had_errors = job_record_has_errors(job_record) if job_record else False
            if had_errors:
                job_set_status(domain, "completed_with_errors", "Recon finished with warnings.")
            else:
                job_set_status(domain, "completed", "Recon finished successfully.")
        except JobCancelled:
            cancelled = True
            log(f"Job {domain} cancelled by user")
            job_set_status(domain, "cancelled", "Job deleted by user.")
        except Exception as exc:
            log(f"Recon pipeline failed for {domain}: {exc}", "error")
            job_set_status(domain, "failed", f"Fatal error: {exc}")
        finally:
            job_to_save = None
            with JOB_LOCK:
                job_record = RUNNING_JOBS.get(domain)
                if job_record and not cancelled:
                    job_to_save = copy.deepcopy({k: v for k, v in job_record.items() if k != "thread"})
                RUNNING_JOBS.pop(domain, None)

            if job_to_save:
                add_completed_job(domain, job_to_save)

            schedule_jobs()
            cleanup_job_control(domain)
            persist_active_jobs()

    thread = threading.Thread(target=runner, name=f"pipeline-{domain}", daemon=True)
    with JOB_LOCK:
        job["thread"] = thread
        job["started"] = datetime.now(timezone.utc).isoformat()
        # Start thread while holding lock to prevent race condition
        # This ensures count_active_jobs_locked() sees the thread immediately
        thread.start()
    job_log_append(domain, "Job dispatched to worker.", "scheduler")


def schedule_jobs() -> None:
    """
    Schedule queued jobs to run, respecting MAX_RUNNING_JOBS limit.
    Starts jobs one at a time while holding the lock to prevent race conditions.
    """
    while True:
        job_to_start = None
        with JOB_LOCK:
            # Check if we can start another job
            if not JOB_QUEUE or count_active_jobs_locked() >= MAX_RUNNING_JOBS:
                break
            
            # Get next job from queue
            domain = JOB_QUEUE.popleft()
            job = RUNNING_JOBS.get(domain)
            
            # Skip if job doesn't exist or already has a thread
            if not job or job.get("thread"):
                continue
            
            job["status"] = "dispatching"
            job["message"] = "Preparing to start."
            job_to_start = job
        
        # Start the job (this acquires JOB_LOCK internally)
        if job_to_start:
            _start_job_thread(job_to_start)


# ================== JOB PERSISTENCE (survive restarts) ==================
#
# Active (queued/running/paused) jobs are snapshotted to disk so an app restart
# can re-dispatch them. Re-dispatch is safe because the pipeline is idempotent:
# per-target flags in state track completed steps, so a resumed job continues
# where it left off rather than redoing finished work.

# Statuses that represent unfinished work worth restoring after a restart.
_ACTIVE_JOB_STATUSES = {"queued", "running", "dispatching", "paused", "pausing"}


def persist_active_jobs() -> None:
    """Snapshot unfinished jobs to disk. Safe to call without holding JOB_LOCK."""
    try:
        with JOB_LOCK:
            snapshot = []
            for domain, job in RUNNING_JOBS.items():
                if job.get("status") not in _ACTIVE_JOB_STATUSES:
                    continue
                snapshot.append({
                    "domain": domain,
                    "wordlist": job.get("wordlist") or "",
                    "skip_nikto": bool(job.get("skip_nikto", False)),
                    "interval": job.get("interval", DEFAULT_INTERVAL),
                    "status": job.get("status"),
                    "queued_at": job.get("queued_at"),
                })
        atomic_write_json(ACTIVE_JOBS_FILE, {"jobs": snapshot})
    except Exception as exc:
        log(f"Failed to persist active jobs: {exc}")


def restore_active_jobs() -> int:
    """Re-dispatch jobs persisted before the last shutdown. Returns count restored."""
    if not ACTIVE_JOBS_FILE.exists():
        return 0
    try:
        with open(ACTIVE_JOBS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        log(f"Could not read active jobs file: {exc}")
        return 0

    jobs = data.get("jobs", []) if isinstance(data, dict) else []
    restored = 0
    for entry in jobs:
        domain = (entry.get("domain") or "").strip().lower()
        if not domain:
            continue
        wordlist = entry.get("wordlist") or None
        skip_nikto = bool(entry.get("skip_nikto", False))
        interval = entry.get("interval") or None
        try:
            ok, msg = start_pipeline_job(domain, wordlist, skip_nikto, interval)
            if ok:
                restored += 1
                job_log_append(domain, "Job restored after app restart; resuming.", "scheduler")
        except Exception as exc:
            log(f"Failed to restore job {domain}: {exc}")
    if restored:
        log(f"Restored {restored} job(s) from before restart; resuming where they left off.")
    return restored


def active_jobs_persist_loop() -> None:
    """Periodically persist active jobs so a crash/restart loses at most ~10s."""
    while True:
        try:
            time.sleep(10)
            persist_active_jobs()
        except Exception:
            # Never let the persister thread die.
            try:
                time.sleep(10)
            except Exception:
                pass


def start_active_jobs_persister() -> None:
    thread = threading.Thread(target=active_jobs_persist_loop, name="active-jobs-persister", daemon=True)
    thread.start()


# ================== WEB COMMAND CENTER ==================


def make_step_entry(status: str = "pending", message: str = "", progress: int = 0) -> Dict[str, Any]:
    return {
        "status": status,
        "message": message,
        "progress": progress,
    }


def init_job_steps(skip_nikto: bool) -> Dict[str, Dict[str, Any]]:
    steps = {step: make_step_entry() for step in PIPELINE_STEPS}
    if skip_nikto:
        steps["nikto"] = make_step_entry(status="skipped", message="Nikto skipped", progress=0)
    return steps


def recalc_job_progress(job: Dict[str, Any]) -> None:
    steps = job.get("steps", {})
    active = [entry for entry in steps.values() if entry.get("status") not in {"skipped"}]
    if not active:
        job["progress"] = 0
        return
    total = len(active)
    total_progress = sum(STEP_PROGRESS.get(entry.get("status"), 0) for entry in active)
    job["progress"] = min(100, max(0, int(total_progress / total)))


def job_set_status(domain: str, status: str, message: Optional[str] = None) -> None:
    if not domain:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if not job:
            return
        job["status"] = status
        if message is not None:
            job["message"] = message
        job["last_update"] = timestamp
        recalc_job_progress(job)
    if message:
        job_log_append(domain, message, source=f"{status.upper()}")


def job_step_update(domain: Optional[str], step: str, *, status: Optional[str] = None,
                    message: Optional[str] = None, progress: Optional[int] = None) -> None:
    if not domain:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if not job:
            return
        step_entry = job.setdefault("steps", {}).setdefault(step, make_step_entry())
        if status is not None:
            step_entry["status"] = status
        if message is not None:
            step_entry["message"] = message
        if progress is not None:
            step_entry["progress"] = max(0, min(100, progress))
        job["last_update"] = timestamp
        recalc_job_progress(job)
    if message:
        job_log_append(domain, f"[{step}] {message}", source=step or "step")


def job_record_has_errors(job: Dict[str, Any]) -> bool:
    return any(entry.get("status") == "error" for entry in job.get("steps", {}).values())
