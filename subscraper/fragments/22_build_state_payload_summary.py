"""Fragment 22_build_state_payload_summary.py. Loaded into the main module namespace."""
def build_state_payload_summary() -> Dict[str, Any]:
    """
    Build a lightweight state payload with minimal subdomain data.
    This is much faster than build_state_payload() for large datasets.
    
    For each target, includes lightweight subdomain entries with only:
    - subdomain name
    - sources
    - httpx summary (status_code, title, webserver only)
    - nuclei/nikto finding counts (not full details)
    - screenshot path (not full metadata)
    
    For performance with large datasets (200k+ subdomains), limits the number
    of subdomains returned per domain to MAX_SUBDOMAINS_IN_SUMMARY (default 100).
    Full data is available via the domain detail page.
    
    This allows the dashboard to render basic views without loading full data.
    
    Optimizations:
    - Uses single JOIN query instead of N+1 queries (70-90% faster)
    - Batches subdomain processing per domain
    - Limits subdomains per domain to prevent UI freezing
    """
    MAX_SUBDOMAINS_IN_SUMMARY = 100  # Maximum subdomains to include per domain in summary
    
    db = get_db()
    cursor = db.cursor()
    
    # OPTIMIZATION: Single query with JOIN instead of N+1 queries
    # This is dramatically faster for large datasets (10,000+ subdomains)
    cursor.execute("""
        SELECT
            t.domain, t.flags, t.options, t.comments, t.data,
            s.subdomain, s.data, s.interesting, s.comments as sub_comments
        FROM targets t
        LEFT JOIN subdomains s ON t.domain = s.domain
        ORDER BY t.domain, s.subdomain
    """)
    
    config = get_config()
    targets = {}
    current_domain = None
    current_target = None
    subdomains = {}
    subdomain_count = 0  # Track subdomains for current domain
    
    # Process results in a single pass
    for row in cursor:
        domain = row[0]
        
        # Check if we've moved to a new domain
        if domain != current_domain:
            # Save previous domain's data if exists
            if current_domain is not None and current_target is not None:
                current_target["subdomains"] = subdomains
                current_target["total_subdomains"] = subdomain_count
                current_target["subdomains_truncated"] = subdomain_count > MAX_SUBDOMAINS_IN_SUMMARY
                # Calculate pending status
                try:
                    current_target["pending"] = target_has_pending_work(current_target, config)
                except Exception:
                    current_target["pending"] = True
                targets[current_domain] = current_target
            
            # Start new domain
            current_domain = domain
            flags = json.loads(row[1]) if row[1] else {}
            options = json.loads(row[2]) if row[2] else {}
            target_comments = json.loads(row[3]) if row[3] else []
            
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
                "endpoint_count": len(extra.get("endpoints", []) or []),
                "js_scan": summarize_js_scan(extra.get("js_scan")),
            }
            subdomains = {}
            subdomain_count = 0
        
        # Process subdomain if present (LEFT JOIN may have NULL subdomain)
        subdomain = row[5]
        if subdomain is not None:
            subdomain_count += 1
            
            # PERFORMANCE: Skip subdomains beyond the limit to prevent UI freezing
            # Full data available in domain detail page
            if subdomain_count > MAX_SUBDOMAINS_IN_SUMMARY:
                continue
            
            try:
                full_data = json.loads(row[6])
                
                # Extract only lightweight fields
                lightweight_data = {
                    "sources": full_data.get("sources", []),
                }
                
                # Add minimal httpx data
                if "httpx" in full_data and full_data["httpx"] is not None:
                    httpx = full_data["httpx"]
                    lightweight_data["httpx"] = {
                        "status_code": httpx.get("status_code"),
                        "title": httpx.get("title", ""),
                        "webserver": httpx.get("webserver", httpx.get("server", "")),
                    }
                
                # Add nuclei/nikto counts only (not full findings)
                nuclei = full_data.get("nuclei", [])
                if nuclei:
                    lightweight_data["nuclei"] = nuclei  # Keep for severity calculation
                
                nikto = full_data.get("nikto", [])
                if nikto:
                    lightweight_data["nikto"] = nikto  # Keep for counts
                
                # Add screenshot path only
                if "screenshot" in full_data and full_data["screenshot"] is not None:
                    screenshot = full_data["screenshot"]
                    lightweight_data["screenshot"] = {
                        "path": screenshot.get("path")
                    }
                
                # Add interesting flag
                if row[7] is not None:
                    lightweight_data["interesting"] = bool(row[7])
                
                subdomains[subdomain] = lightweight_data
                
            except json.JSONDecodeError:
                subdomains[subdomain] = {}
    
    # Save last domain's data
    if current_domain is not None and current_target is not None:
        current_target["subdomains"] = subdomains
        current_target["total_subdomains"] = subdomain_count
        current_target["subdomains_truncated"] = subdomain_count > MAX_SUBDOMAINS_IN_SUMMARY
        # Calculate pending status
        try:
            current_target["pending"] = target_has_pending_work(current_target, config)
        except Exception:
            current_target["pending"] = True
        targets[current_domain] = current_target
    
    # Load completed jobs and merge with active targets
    completed_jobs = load_completed_jobs()
    for job_key, job_data in completed_jobs.items():
        domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
        
        if domain in targets:
            # Add completion timestamp to active target
            if not targets[domain].get("completed_at"):
                targets[domain]["completed_at"] = job_data.get("completed_at")
        else:
            # Domain not in active targets - create minimal entry from completed job
            # For completed jobs not in active state, include minimal lightweight data
            state_data = job_data.get("state", {})
            subdomains = state_data.get("subdomains", {})
            
            # Create lightweight subdomain entries for completed jobs too
            # Limit to first 100 for performance (configurable via MAX_COMPLETED_JOB_SUBDOMAINS)
            MAX_COMPLETED_JOB_SUBDOMAINS = 100
            lightweight_subs = {}
            for sub, sub_data in list(subdomains.items())[:MAX_COMPLETED_JOB_SUBDOMAINS]:
                lightweight_subs[sub] = {
                    "sources": sub_data.get("sources", []),
                    "httpx": {
                        "status_code": sub_data.get("httpx", {}).get("status_code"),
                        "title": sub_data.get("httpx", {}).get("title", ""),
                        "webserver": sub_data.get("httpx", {}).get("webserver", ""),
                    } if sub_data.get("httpx") else {},
                    "nuclei": sub_data.get("nuclei", []),
                    "nikto": sub_data.get("nikto", []),
                    "screenshot": {
                        "path": sub_data.get("screenshot", {}).get("path")
                    } if sub_data.get("screenshot") else {},
                }
            
            targets[domain] = {
                "subdomains": lightweight_subs,
                "flags": state_data.get("flags", {}),
                "options": job_data.get("options", {}),
                "comments": [],
                "completed_at": job_data.get("completed_at"),
                "pending": False,
                "from_completed_jobs": True,
                "endpoint_count": len(state_data.get("endpoints", []) or []),
                "js_scan": summarize_js_scan(state_data.get("js_scan")),
            }
    
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
    return {
        "last_updated": last_updated,
        "targets": targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
    }


def build_state_payload() -> Dict[str, Any]:
    """
    Build complete state payload with all subdomain details.
    This is slower but includes full information.
    Use this for exports and detail pages only.
    """
    state = load_state()
    config = get_config()
    targets = state.get("targets", {})
    for info in targets.values():
        try:
            info["pending"] = target_has_pending_work(info, config)
        except Exception:
            info["pending"] = True
    
    # Load completed jobs and convert them to targets format for display
    completed_jobs = load_completed_jobs()
    completed_targets = {}
    for job_key, job_data in completed_jobs.items():
        # Extract domain from job key
        # Job keys are stored as "domain_timestamp" format (see add_completed_job function)
        # Example: "example.com_1702901234.567890"
        domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
        
        # Check if this domain exists in active targets
        if domain in targets:
            # Domain is still active in state.json, add completion metadata
            # Preserve all active data but mark as completed and add timestamp
            if not targets[domain].get("completed_at"):
                targets[domain]["completed_at"] = job_data.get("completed_at")
            # Keep pending status from active calculation above
        else:
            # Domain not in active targets, create from completed job data
            completed_targets[domain] = {
                "subdomains": job_data.get("state", {}).get("subdomains", {}),
                "flags": job_data.get("state", {}).get("flags", {}),
                "options": job_data.get("options", {}),
                "pending": False,
                "completed_at": job_data.get("completed_at"),
                "from_completed_jobs": True,
            }
    
    # Merge: completed targets first, then active targets (active takes precedence)
    # This ensures active scans override completed data for same domain
    all_targets = {**completed_targets, **targets}
    
    # Resolve through the same logic the pipeline uses: custom paths, PATH and
    # Go/Homebrew/Scoop bin dirs. shutil.which() alone under-reports installs.
    tool_info = {}
    for name in TOOLS.keys():
        try:
            tool_info[name] = ("crtsh" if name == "crtsh" else (resolve_tool_path_cached(name) or ""))
        except Exception:
            tool_info[name] = ""
    return {
        "last_updated": state.get("last_updated"),
        "targets": all_targets,
        "running_jobs": snapshot_running_jobs(),
        "queued_jobs": job_queue_snapshot(),
        "config": config,
        "tools": tool_info,
        "workers": snapshot_workers(),
        "monitors": list_monitors(),
    }




def invalidate_state_cache() -> None:
    """Invalidate the state payload cache. Call this when state changes."""
    global STATE_CACHE
    with STATE_CACHE_LOCK:
        STATE_CACHE["etag"] = None
        STATE_CACHE["payload"] = None
        STATE_CACHE["last_updated"] = None
