"""Fragment 15_gather_js_urls.py. Loaded into the main module namespace."""
def _gather_js_urls(domain: str, state: Dict[str, Any], config: Dict[str, Any]) -> List[str]:
    """Collect candidate JS URLs from archived endpoints and live-host HTML."""
    tgt = ensure_target_state(state, domain)
    submap = tgt.get("subdomains", {})
    max_html = int(config.get("js_scan_max_html_hosts", 60) or 60)

    js_urls: set = set()

    # 1) Archived endpoints ending in .js
    for url in tgt.get("endpoints", []) or []:
        base = url.split("?", 1)[0].lower()
        if base.endswith(".js") or base.endswith(".mjs"):
            js_urls.add(url)

    # 2) Parse live-host HTML for <script src=...>
    live_urls: List[str] = []
    for host, entry in submap.items():
        httpx = (entry or {}).get("httpx") or {}
        url = httpx.get("url")
        status = httpx.get("status_code")
        if url and status and status != 0:
            live_urls.append(url)
    live_urls = live_urls[:max_html]

    script_re = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    for base_url in live_urls:
        html = _js_fetch(base_url, timeout=12, max_bytes=2_000_000)
        if not html:
            continue
        for src in script_re.findall(html):
            src = src.strip()
            if not src or src.startswith("data:"):
                continue
            try:
                absolute = urljoin(base_url, src)
            except ValueError:
                continue
            path = absolute.split("?", 1)[0].lower()
            if path.endswith(".js") or path.endswith(".mjs"):
                js_urls.add(absolute)

    return sorted(js_urls)


def run_js_scan(domain: str, config: Dict[str, Any],
                job_domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Gather JS assets for a target and scan them for secrets, hidden endpoints
    and parameters. Persists results under target['js_scan'] and returns it.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    state = load_state()
    js_urls = _gather_js_urls(domain, state, config)
    max_files = int(config.get("js_scan_max_files", 300) or 300)
    truncated = len(js_urls) > max_files
    if truncated:
        js_urls = js_urls[:max_files]

    if job_domain:
        job_log_append(job_domain, f"JS scan: {len(js_urls)} JS file(s) to fetch.", "jsscan")

    files: List[Dict[str, Any]] = []
    all_secrets: List[Dict[str, Any]] = []
    endpoint_set: set = set()
    param_set: set = set()
    seen_secret_keys: set = set()

    def worker(u: str) -> Optional[Dict[str, Any]]:
        text = _js_fetch(u)
        if text is None:
            return {"url": u, "ok": False, "size": 0, "secrets": 0, "endpoints": 0}
        res = scan_js_content(text, u)
        return {"url": u, "ok": True, "size": len(text), "result": res}

    workers = max(1, min(10, int(config.get("js_scan_workers", 8) or 8)))
    if js_urls:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(worker, u): u for u in js_urls}
            for fut in as_completed(futures):
                try:
                    item = fut.result()
                except Exception:
                    continue
                if not item:
                    continue
                if not item.get("ok"):
                    files.append(item)
                    continue
                res = item.pop("result")
                for sec in res["secrets"]:
                    key = (sec["type"], sec["match"], sec["source"])
                    if key in seen_secret_keys:
                        continue
                    seen_secret_keys.add(key)
                    all_secrets.append(sec)
                endpoint_set.update(res["endpoints"])
                param_set.update(res["params"])
                files.append({
                    "url": item["url"],
                    "ok": True,
                    "size": item["size"],
                    "secrets": len(res["secrets"]),
                    "endpoints": len(res["endpoints"]),
                })

    # Cap stored lists to keep state lean.
    endpoints_sorted = sorted(endpoint_set)[:5000]
    params_sorted = sorted(param_set)[:2000]
    all_secrets = all_secrets[:1000]

    js_scan = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "files": sorted(files, key=lambda f: (not f.get("ok"), f.get("url", ""))),
        "secrets": all_secrets,
        "endpoints": endpoints_sorted,
        "params": params_sorted,
        "truncated": truncated,
        "summary": {
            "files": len(files),
            "files_ok": sum(1 for f in files if f.get("ok")),
            "secrets": len(all_secrets),
            "endpoints": len(endpoints_sorted),
            "params": len(params_sorted),
        },
    }

    # Persist.
    state = load_state()
    tgt = ensure_target_state(state, domain)
    tgt["js_scan"] = js_scan
    # Merge discovered endpoints into the target endpoints list too.
    existing = set(tgt.get("endpoints", []) or [])
    for ep in endpoints_sorted:
        if ep.startswith("http") and ep not in existing:
            existing.add(ep)
    tgt["endpoints"] = sorted(existing)[:20000]
    save_state(state)

    if job_domain:
        s = js_scan["summary"]
        job_log_append(
            job_domain,
            f"JS scan done: {s['files_ok']}/{s['files']} files, "
            f"{s['secrets']} secret(s), {s['endpoints']} endpoint(s), {s['params']} param(s).",
            "jsscan",
        )
    return js_scan


def summarize_js_scan(js_scan: Optional[Dict[str, Any]], max_secrets: int = 5) -> Optional[Dict[str, Any]]:
    """
    Lightweight view of a target's JS scan for list/overview payloads: counts,
    a breakdown by secret type and a few sample hits. Full detail stays on the
    domain page.
    """
    if not isinstance(js_scan, dict):
        return None
    secrets = js_scan.get("secrets") or []
    endpoints = js_scan.get("endpoints") or []
    params = js_scan.get("params") or []
    files = js_scan.get("files") or []
    summary = js_scan.get("summary") or {}

    secret_types: Dict[str, int] = {}
    for secret in secrets:
        if isinstance(secret, dict):
            secret_types[str(secret.get("type") or "unknown")] = \
                secret_types.get(str(secret.get("type") or "unknown"), 0) + 1

    return {
        "scanned_at": js_scan.get("scanned_at"),
        "truncated": bool(js_scan.get("truncated")),
        "summary": {
            "files": int(summary.get("files", len(files)) or 0),
            "files_ok": int(summary.get("files_ok", 0) or 0),
            "secrets": int(summary.get("secrets", len(secrets)) or 0),
            "endpoints": int(summary.get("endpoints", len(endpoints)) or 0),
            "params": int(summary.get("params", len(params)) or 0),
        },
        "secret_types": secret_types,
        "top_secrets": [
            {"type": secret.get("type"), "match": secret.get("match"), "source": secret.get("source")}
            for secret in secrets[:max_secrets] if isinstance(secret, dict)
        ],
    }


def js_findings_overview(limit_targets: int = 10, limit_secrets: int = 10) -> Dict[str, Any]:
    """
    Cross-target rollup of JS scan results for the dashboard overview, so JS
    secrets are visible without opening each domain.
    """
    state = load_state()
    per_target: List[Dict[str, Any]] = []
    recent_secrets: List[Dict[str, Any]] = []
    totals = {"secrets": 0, "endpoints": 0, "params": 0, "files": 0, "targets_scanned": 0}
    secret_types: Dict[str, int] = {}

    for domain, target in (state.get("targets", {}) or {}).items():
        if not isinstance(target, dict):
            continue
        summary = summarize_js_scan(target.get("js_scan"))
        if not summary:
            continue
        totals["targets_scanned"] += 1
        counts = summary["summary"]
        for key in ("secrets", "endpoints", "params", "files"):
            totals[key] += counts.get(key, 0)
        for secret_type, count in summary["secret_types"].items():
            secret_types[secret_type] = secret_types.get(secret_type, 0) + count
        per_target.append({
            "domain": domain,
            "scanned_at": summary["scanned_at"],
            "counts": counts,
            "secret_types": summary["secret_types"],
        })
        for secret in (target.get("js_scan") or {}).get("secrets", [])[:limit_secrets]:
            if isinstance(secret, dict):
                recent_secrets.append({
                    "domain": domain,
                    "type": secret.get("type"),
                    "match": secret.get("match"),
                    "source": secret.get("source"),
                })

    per_target.sort(key=lambda item: (-item["counts"].get("secrets", 0), item["domain"]))
    recent_secrets.sort(key=lambda item: (item["domain"], str(item.get("type") or "")))
    return {
        "totals": totals,
        "secret_types": secret_types,
        "targets": per_target[:limit_targets],
        "targets_with_findings": sum(1 for item in per_target if item["counts"].get("secrets", 0)),
        "secrets": recent_secrets[:limit_secrets],
    }
