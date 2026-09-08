"""Fragment 23_build_state_payload_paginated.py. Loaded into the main module namespace."""
def build_state_payload_paginated(page: int = 1, per_page: int = 50, full: bool = False) -> Dict[str, Any]:
    """
    Build state payload with pagination support for large datasets.
    
    Args:
        page: Page number (1-indexed)
        per_page: Number of targets per page
        full: If True, return full data; if False, return summary
    
    Returns:
        Dict with paginated targets and metadata
    
    Optimizations:
    - Only loads requested page of targets from database
    - Includes pagination metadata (total_targets, total_pages, current_page)
    - Reduces memory usage and response time for large datasets
    """
    db = get_db()
    cursor = db.cursor()
    config = get_config()
    
    # Calculate pagination
    offset = (page - 1) * per_page
    
    # Get total count for pagination metadata
    cursor.execute("SELECT COUNT(*) FROM targets")
    total_targets = cursor.fetchone()[0]
    total_pages = (total_targets + per_page - 1) // per_page  # Ceiling division
    
    # Load paginated targets with subdomains using optimized JOIN
    if full:
        # Full data: load everything for the page
        cursor.execute("""
            SELECT 
                t.domain, t.flags, t.options, t.comments,
                s.subdomain, s.data, s.interesting, s.comments as sub_comments
            FROM (
                SELECT domain, flags, options, comments
                FROM targets
                ORDER BY domain
                LIMIT ? OFFSET ?
            ) t
            LEFT JOIN subdomains s ON t.domain = s.domain
            ORDER BY t.domain, s.subdomain
        """, (per_page, offset))
    else:
        # Summary data: lightweight fields only
        cursor.execute("""
            SELECT 
                t.domain, t.flags, t.options, t.comments,
                s.subdomain, s.data, s.interesting, s.comments as sub_comments
            FROM (
                SELECT domain, flags, options, comments
                FROM targets
                ORDER BY domain
                LIMIT ? OFFSET ?
            ) t
            LEFT JOIN subdomains s ON t.domain = s.domain
            ORDER BY t.domain, s.subdomain
        """, (per_page, offset))
    
    targets = {}
    current_domain = None
    current_target = None
    subdomains = {}
    
    # Process results (same logic as non-paginated version)
    for row in cursor:
        domain = row[0]
        
        if domain != current_domain:
            if current_domain is not None and current_target is not None:
                current_target["subdomains"] = subdomains
                if not full:
                    try:
                        current_target["pending"] = target_has_pending_work(current_target, config)
                    except Exception:
                        current_target["pending"] = True
                targets[current_domain] = current_target
            
            current_domain = domain
            flags = json.loads(row[1]) if row[1] else {}
            options = json.loads(row[2]) if row[2] else {}
            target_comments = json.loads(row[3]) if row[3] else []
            
            current_target = {
                "flags": flags,
                "options": options,
                "comments": target_comments,
            }
            subdomains = {}
        
        subdomain = row[4]
        if subdomain is not None:
            try:
                full_data = json.loads(row[5])
                
                if full:
                    # Full data: include everything
                    if row[6] is not None:
                        full_data["interesting"] = bool(row[6])
                    if row[7]:
                        full_data["comments"] = json.loads(row[7])
                    subdomains[subdomain] = full_data
                else:
                    # Summary: lightweight fields only
                    lightweight_data = {
                        "sources": full_data.get("sources", []),
                    }
                    
                    if "httpx" in full_data and full_data["httpx"] is not None:
                        httpx = full_data["httpx"]
                        lightweight_data["httpx"] = {
                            "status_code": httpx.get("status_code"),
                            "title": httpx.get("title", ""),
                            "webserver": httpx.get("webserver", httpx.get("server", "")),
                        }
                    
                    nuclei = full_data.get("nuclei", [])
                    if nuclei:
                        lightweight_data["nuclei"] = nuclei
                    
                    nikto = full_data.get("nikto", [])
                    if nikto:
                        lightweight_data["nikto"] = nikto
                    
                    if "screenshot" in full_data and full_data["screenshot"] is not None:
                        screenshot = full_data["screenshot"]
                        lightweight_data["screenshot"] = {
                            "path": screenshot.get("path")
                        }
                    
                    if row[6] is not None:
                        lightweight_data["interesting"] = bool(row[6])
                    
                    subdomains[subdomain] = lightweight_data
                
            except json.JSONDecodeError:
                subdomains[subdomain] = {}
    
    # Save last domain
    if current_domain is not None and current_target is not None:
        current_target["subdomains"] = subdomains
        if not full:
            try:
                current_target["pending"] = target_has_pending_work(current_target, config)
            except Exception:
                current_target["pending"] = True
        targets[current_domain] = current_target
    
    # Get last updated time
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    # Resolve through the same logic the pipeline uses: custom paths, PATH and
    # Go/Homebrew/Scoop bin dirs. shutil.which() alone under-reports installs.
    tool_info = {}
    for name in TOOLS.keys():
        try:
            tool_info[name] = ("crtsh" if name == "crtsh" else (resolve_tool_path_cached(name) or ""))
        except Exception:
            tool_info[name] = ""
    
    payload = {
        "last_updated": last_updated,
        "targets": targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
        # Pagination metadata
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_targets": total_targets,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
    }
    
    # For full payload, merge completed jobs (like non-paginated version)
    if full:
        completed_jobs = load_completed_jobs()
        for job_key, job_data in completed_jobs.items():
            domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
            if domain in targets:
                if not targets[domain].get("completed_at"):
                    targets[domain]["completed_at"] = job_data.get("completed_at")
    
    return payload


def get_cached_state_payload(full: bool = False) -> Tuple[str, Dict[str, Any]]:
    """
    Get state payload with caching support.
    Returns (etag, payload) tuple.
    
    Args:
        full: If True, returns full payload. If False, returns summary.
    
    Returns:
        Tuple of (etag_string, payload_dict)
    """
    global STATE_CACHE
    
    # Get current last_updated time from database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT MAX(updated_at) FROM targets")
    last_updated_row = cursor.fetchone()
    current_last_updated = last_updated_row[0] if last_updated_row and last_updated_row[0] else None
    
    # Check if we have a valid cache
    cache_key = f"{'full' if full else 'summary'}:{current_last_updated}"
    etag = hashlib.md5(cache_key.encode()).hexdigest()
    
    with STATE_CACHE_LOCK:
        if STATE_CACHE.get("etag") == etag and STATE_CACHE.get("payload") is not None:
            # Cache hit - return cached payload
            return etag, STATE_CACHE["payload"]
        
        # Cache miss - build new payload
        if full:
            payload = build_state_payload()
        else:
            payload = build_state_payload_summary()
        
        # Update cache
        STATE_CACHE["etag"] = etag
        STATE_CACHE["payload"] = payload
        STATE_CACHE["last_updated"] = current_last_updated
        
        return etag, payload
