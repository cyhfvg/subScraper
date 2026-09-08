"""Fragment 28_touch_program_investigated.py. Loaded into the main module namespace."""
def _touch_program_investigated(program_id: str) -> None:
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT data FROM programs WHERE id = ?", (program_id,))
    row = cursor.fetchone()
    if not row:
        return
    try:
        data = json.loads(row["data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        data = {}
    data["last_investigated_at"] = _now_iso()
    cursor.execute("UPDATE programs SET data = ?, updated_at = ? WHERE id = ?",
                   (json.dumps(data), _now_iso(), program_id))
    db.commit()


# --- Investigation ----------------------------------------------------------

def investigate_program(program: Dict[str, Any], options: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Dispatch the recon pipeline for every in-scope root of a program.
    Targets outside the program scope are refused, not silently dropped.
    """
    scope = program.get("scope", {})
    roots = program_root_targets(program)
    requested = options.get("targets")
    refused: List[Dict[str, str]] = []

    if requested:
        if isinstance(requested, str):
            requested = _clean_scope_list(requested)
        selected: List[str] = []
        for target in requested:
            host = _scope_pattern_host(str(target))
            if not host:
                refused.append({"target": str(target), "reason": "Not a valid hostname."})
                continue
            while host.startswith("*."):
                host = host[2:]
            verdict = evaluate_asset_scope(host, scope.get("in_scope", []), scope.get("out_of_scope", []))
            if not verdict["in_scope"]:
                refused.append({"target": host, "reason": verdict["reason"]})
                continue
            if host not in selected:
                selected.append(host)
        roots = selected

    if not roots:
        return False, "No in-scope targets to investigate.", {"dispatched": [], "refused": refused}

    cfg = get_config()
    skip_nikto = bool_from_value(options.get("skip_nikto"), cfg.get("skip_nikto_by_default", False))
    wordlist = options.get("wordlist")
    interval = options.get("interval")
    interval_int: Optional[int] = None
    if interval not in (None, ""):
        try:
            interval_int = int(interval)
        except (TypeError, ValueError):
            interval_int = None

    dispatched: List[Dict[str, Any]] = []
    for root in roots:
        success, message = start_pipeline_job(root, wordlist, skip_nikto, interval_int)
        dispatched.append({"target": root, "success": success, "message": message})

    _touch_program_investigated(program["id"])
    started = [item["target"] for item in dispatched if item["success"]]
    message = f"Dispatched {len(started)}/{len(roots)} target(s) for program '{program['id']}'."
    if refused:
        message += f" Refused {len(refused)} out-of-scope target(s)."
    return bool(started), message, {"dispatched": dispatched, "refused": refused}


def _job_snapshot(domain: str) -> Optional[Dict[str, Any]]:
    with JOB_LOCK:
        job = RUNNING_JOBS.get(domain)
        if job:
            return {
                "status": job.get("status"),
                "message": job.get("message"),
                "progress": job.get("progress", 0),
                "queued_at": job.get("queued_at"),
                "started": job.get("started"),
                "last_update": job.get("last_update"),
                "steps": {name: {"status": step.get("status"), "progress": step.get("progress", 0),
                                 "message": step.get("message", "")}
                          for name, step in (job.get("steps") or {}).items()},
            }
    completed = COMPLETED_JOBS.get(domain)
    if completed:
        return {
            "status": completed.get("status", "completed"),
            "message": completed.get("message", ""),
            "progress": completed.get("progress", 100),
            "completed_at": completed.get("completed_at"),
            "steps": {name: {"status": step.get("status"), "progress": step.get("progress", 0),
                             "message": step.get("message", "")}
                      for name, step in (completed.get("steps") or {}).items()},
        }
    return None


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in SEVERITY_ORDER:
        return text
    if text in ("informational", "information"):
        return "info"
    return "unknown"


def _severity_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for item in items:
        counts[_normalize_severity(item.get("severity"))] += 1
    return counts


def _program_targets_from_state(program: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Recon state entries that belong to this program's roots."""
    roots = program_root_targets(program)
    targets = state.get("targets", {}) or {}
    return {root: targets[root] for root in roots if root in targets}


def program_status(program: Dict[str, Any]) -> Dict[str, Any]:
    """Per-root pipeline progress plus aggregate coverage for the whole program."""
    state = load_state()
    roots = program_root_targets(program)
    targets = state.get("targets", {}) or {}
    scope = program.get("scope", {})

    per_target: List[Dict[str, Any]] = []
    totals = {"subdomains": 0, "live_hosts": 0, "endpoints": 0, "findings": 0}
    severity_totals = {sev: 0 for sev in SEVERITY_ORDER}

    for root in roots:
        target = targets.get(root)
        job = _job_snapshot(root)
        if not target:
            per_target.append({
                "target": root,
                "scanned": False,
                "job": job,
                "flags": {},
                "counts": {"subdomains": 0, "live_hosts": 0, "endpoints": 0, "findings": 0},
            })
            continue

        subs = target.get("subdomains", {}) or {}
        live = sum(1 for entry in subs.values() if isinstance(entry, dict) and entry.get("httpx"))
        findings = 0
        for entry in subs.values():
            if not isinstance(entry, dict):
                continue
            for finding in (entry.get("nuclei") or []):
                severity_totals[_normalize_severity(finding.get("severity"))] += 1
                findings += 1
            for finding in (entry.get("nikto") or []):
                severity_totals[_normalize_severity(finding.get("severity"))] += 1
                findings += 1
        js_secrets = len(((target.get("js_scan") or {}).get("secrets") or []))
        endpoints = len(target.get("endpoints", []) or [])

        totals["subdomains"] += len(subs)
        totals["live_hosts"] += live
        totals["endpoints"] += endpoints
        totals["findings"] += findings + js_secrets

        per_target.append({
            "target": root,
            "scanned": True,
            "job": job,
            "flags": target.get("flags", {}),
            "pending_work": target_has_pending_work(target),
            "counts": {
                "subdomains": len(subs),
                "live_hosts": live,
                "endpoints": endpoints,
                "findings": findings,
                "js_secrets": js_secrets,
            },
        })

    active = [item["target"] for item in per_target
              if item.get("job") and item["job"].get("status") in ("queued", "running", "paused")]
    return {
        "program": {"id": program["id"], "name": program["name"], "platform": program["platform"]},
        "scope_summary": {
            "in_scope_entries": len(scope.get("in_scope", [])),
            "out_of_scope_entries": len(scope.get("out_of_scope", [])),
            "root_targets": len(roots),
        },
        "targets": per_target,
        "active_targets": active,
        "investigation_state": "running" if active else ("complete" if roots and all(
            item["scanned"] and not item.get("pending_work") for item in per_target) else "idle"),
        "totals": totals,
        "severity_totals": severity_totals,
        "last_investigated_at": program.get("last_investigated_at"),
    }


def _paginate(items: List[Any], page: int, per_page: int) -> Tuple[List[Any], Dict[str, Any]]:
    total = len(items)
    per_page = max(1, min(1000, per_page))
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    return items[start:start + per_page], {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_next": page < pages,
    }


def collect_program_assets(program: Dict[str, Any], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten every discovered host for a program into agent-friendly records.
    Out-of-scope hosts are excluded unless explicitly requested.
    """
    state = load_state()
    scope = program.get("scope", {})
    in_scope = scope.get("in_scope", []) or []
    out_of_scope = scope.get("out_of_scope", []) or []
    include_out = bool_from_value(filters.get("include_out_of_scope"), False)
    live_only = bool_from_value(filters.get("live_only"), False)
    interesting_only = bool_from_value(filters.get("interesting_only"), False)
    with_findings = bool_from_value(filters.get("with_findings"), False)
    search = str(filters.get("search") or "").strip().lower()
    status_filter = str(filters.get("status_code") or "").strip()

    assets: List[Dict[str, Any]] = []
    for root, target in _program_targets_from_state(program, state).items():
        for host, entry in (target.get("subdomains", {}) or {}).items():
            if not isinstance(entry, dict):
                continue
            verdict = evaluate_asset_scope(host, in_scope, out_of_scope)
            if not verdict["in_scope"] and not include_out:
                continue
            httpx = entry.get("httpx") or {}
            nuclei = entry.get("nuclei") or []
            nikto = entry.get("nikto") or []
            record = {
                "host": host,
                "root": root,
                "in_scope": verdict["in_scope"],
                "scope_reason": verdict["reason"],
                "sources": entry.get("sources", []),
                "live": bool(httpx),
                "url": httpx.get("url"),
                "status_code": httpx.get("status_code"),
                "title": httpx.get("title"),
                "webserver": httpx.get("webserver"),
                "tech": httpx.get("tech") or [],
                "content_length": httpx.get("content_length"),
                "screenshot": entry.get("screenshot"),
                "interesting": bool(entry.get("interesting")),
                "findings": {"nuclei": len(nuclei), "nikto": len(nikto)},
                "severity_counts": _severity_counts(list(nuclei) + list(nikto)),
            }
            if live_only and not record["live"]:
                continue
            if interesting_only and not record["interesting"]:
                continue
            if with_findings and not (nuclei or nikto):
                continue
            if status_filter and str(record["status_code"] or "") != status_filter:
                continue
            if search and search not in host:
                continue
            assets.append(record)

    assets.sort(key=lambda item: (not item["live"], item["host"]))
    return assets


def program_assets(program: Dict[str, Any], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Paginated view over collect_program_assets()."""
    assets = collect_program_assets(program, filters)
    try:
        page = max(1, int(filters.get("page") or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(filters.get("per_page") or 100)
    except (TypeError, ValueError):
        per_page = 100
    items, pagination = _paginate(assets, page, per_page)
    return {"program_id": program["id"], "assets": items, "pagination": pagination}


def program_findings(program: Dict[str, Any], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Normalized findings across nuclei, nikto and JS secret scanning."""
    state = load_state()
    scope = program.get("scope", {})
    in_scope = scope.get("in_scope", []) or []
    out_of_scope = scope.get("out_of_scope", []) or []
    include_out = bool_from_value(filters.get("include_out_of_scope"), False)
    severity_filter = {s.strip().lower() for s in str(filters.get("severity") or "").split(",") if s.strip()}
    source_filter = {s.strip().lower() for s in str(filters.get("source") or "").split(",") if s.strip()}
    host_filter = str(filters.get("host") or "").strip().lower()

    findings: List[Dict[str, Any]] = []

    def _add(source: str, host: str, root: str, severity: str, name: str, extra: Dict[str, Any]) -> None:
        record = {
            "id": hashlib.sha256(f"{source}|{host}|{name}|{extra.get('matched_at') or ''}".encode("utf-8")).hexdigest()[:16],
            "source": source,
            "host": host,
            "root": root,
            "severity": _normalize_severity(severity),
            "name": name,
        }
        record.update(extra)
        findings.append(record)

    for root, target in _program_targets_from_state(program, state).items():
        for host, entry in (target.get("subdomains", {}) or {}).items():
            if not isinstance(entry, dict):
                continue
            if not include_out and not evaluate_asset_scope(host, in_scope, out_of_scope)["in_scope"]:
                continue
            for finding in (entry.get("nuclei") or []):
                _add("nuclei", host, root, finding.get("severity"),
                     finding.get("name") or finding.get("template_id") or "nuclei finding",
                     {"template_id": finding.get("template_id"), "matched_at": finding.get("matched_at")})
            for finding in (entry.get("nikto") or []):
                _add("nikto", host, root, finding.get("severity"),
                     finding.get("msg") or "nikto finding",
                     {"matched_at": finding.get("uri"), "cve": finding.get("cve"), "osvdb": finding.get("osvdb")})

        js_scan = target.get("js_scan") or {}
        for secret in (js_scan.get("secrets") or []):
            source_url = secret.get("source") or ""
            host = _scope_pattern_host(source_url) or root
            if not include_out and not evaluate_asset_scope(host, in_scope, out_of_scope)["in_scope"]:
                continue
            _add("js_secret", host, root, "medium",
                 f"Possible {secret.get('type', 'secret')} in JS",
                 {"matched_at": source_url, "match": secret.get("match")})

    if severity_filter:
        findings = [f for f in findings if f["severity"] in severity_filter]
    if source_filter:
        findings = [f for f in findings if f["source"] in source_filter]
    if host_filter:
        findings = [f for f in findings if host_filter in f["host"]]

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["host"]))
    try:
        page = max(1, int(filters.get("page") or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(filters.get("per_page") or 100)
    except (TypeError, ValueError):
        per_page = 100
    items, pagination = _paginate(findings, page, per_page)
    return {
        "program_id": program["id"],
        "findings": items,
        "pagination": pagination,
        "severity_counts": _severity_counts(findings),
    }


def program_endpoints(program: Dict[str, Any], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Archived and JS-discovered URLs for the program, plus JS-derived parameters."""
    state = load_state()
    search = str(filters.get("search") or "").strip().lower()
    endpoints: List[Dict[str, Any]] = []
    params: set = set()
    for root, target in _program_targets_from_state(program, state).items():
        for url in (target.get("endpoints", []) or []):
            if search and search not in url.lower():
                continue
            endpoints.append({"url": url, "root": root})
        params.update((target.get("js_scan") or {}).get("params") or [])

    try:
        page = max(1, int(filters.get("page") or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(filters.get("per_page") or 200)
    except (TypeError, ValueError):
        per_page = 200
    items, pagination = _paginate(endpoints, page, per_page)
    return {
        "program_id": program["id"],
        "endpoints": items,
        "params": sorted(params)[:2000],
        "pagination": pagination,
    }
