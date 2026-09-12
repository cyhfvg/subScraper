"""Fragment 16_run_downstream_pipeline.py. Loaded into the main module namespace."""
def run_downstream_pipeline(
    domain: str,
    wordlist: Optional[str],
    config: Dict[str, Any],
    skip_nikto: bool,
    interval: int,
    job_domain: Optional[str],
    enumerators_done_event: threading.Event,
) -> None:
    def update_step(step_name: str, status: Optional[str] = None,
                    message: Optional[str] = None, progress: Optional[int] = None) -> None:
        job_step_update(job_domain, step_name, status=status, message=message, progress=progress)

    def wait_for_subdomains() -> List[str]:
        while True:
            state = load_state()
            tgt = ensure_target_state(state, domain)
            subs = sorted(tgt["subdomains"].keys())
            if subs or enumerators_done_event.is_set():
                return subs
            job_sleep(job_domain, 5)

    all_subs = wait_for_subdomains()
    log(f"Total unique hosts for {domain}: {len(all_subs)}")
    parsed = parse_scan_target(domain)
    subs_file = write_subdomains_file(domain, all_subs)

    state = load_state()
    flags = ensure_target_state(state, domain)["flags"]

    # ---------- dnsx (DNS verification, domain hosts only) ----------
    skip_dnsx = bool(parsed and parsed.is_network)
    if skip_dnsx:
        flags["dnsx_done"] = True
        save_state(state)
        update_step("dnsx", status="skipped", message="IP/CIDR target; dnsx skipped.", progress=0)
    elif not flags.get("dnsx_done") and config.get("enable_dnsx", True):
        tgt_state = ensure_target_state(state, domain)
        all_discovered_subs = sorted(tgt_state["subdomains"].keys())
        name_hosts = [h for h in all_discovered_subs if not is_ip_or_cidr(h)]
        if name_hosts:
            log(f"=== dnsx DNS verification for {domain} ({len(name_hosts)} hosts) ===")
            update_step("dnsx", status="running", message=f"Verifying {len(name_hosts)} hosts with dnsx", progress=50)
            if job_domain:
                job_log_append(job_domain, "Waiting for dnsx slot...", "scheduler")
            with TOOL_GATES["dnsx"]:
                if job_domain:
                    job_log_append(job_domain, "dnsx slot acquired.", "scheduler")
                verified_subs = dnsx_verify(name_hosts, domain, job_domain=job_domain, config=config)
            log(f"dnsx verified {len(verified_subs)} resolving hosts.")
            flags["dnsx_done"] = True
            save_state(state)
            update_step("dnsx", status="completed", message=f"dnsx verified {len(verified_subs)}/{len(name_hosts)} hosts resolve.", progress=100)
        else:
            flags["dnsx_done"] = True
            save_state(state)
            update_step("dnsx", status="skipped", message="No hostnames to verify.", progress=0)
    elif not config.get("enable_dnsx", True):
        update_step("dnsx", status="skipped", message="dnsx disabled in settings.", progress=0)
        flags["dnsx_done"] = True
        save_state(state)
    else:
        update_step("dnsx", status="skipped", message="dnsx already completed for this target.", progress=0)

    # ---------- nmap port scan + service detection ----------
    web_urls: List[str] = list(ensure_target_state(state, domain).get("web_urls") or [])
    if not flags.get("port_scan_done") and config.get("enable_port_scan", True):
        state = load_state()
        tgt_state = ensure_target_state(state, domain)
        flags = tgt_state["flags"]
        nmap_targets = sorted(tgt_state["subdomains"].keys())
        if parsed is not None and parsed.is_network:
            nmap_targets = [parsed.normalized]
        elif not nmap_targets and parsed is not None:
            nmap_targets = [parsed.normalized]
        if nmap_targets:
            update_step("port_scan", status="running", message=f"nmap scanning {len(nmap_targets)} targets", progress=40)
            scanned = port_scan_hosts(nmap_targets, domain, config=config, job_domain=job_domain)
            state = load_state()
            web_urls = enrich_state_with_ports(state, domain, scanned)
            tgt_state = ensure_target_state(state, domain)
            tgt_state["web_urls"] = web_urls
            flags = tgt_state["flags"]
            flags["port_scan_done"] = True
            save_state(state)
            update_step("port_scan", status="completed", message=f"nmap found {len(scanned)} live hosts, {len(web_urls)} web endpoints.", progress=100)
            job_log_append(job_domain, f"nmap live hosts={len(scanned)} web={len(web_urls)}", "port_scan")
        else:
            flags["port_scan_done"] = True
            save_state(state)
            update_step("port_scan", status="skipped", message="No hosts to port-scan.", progress=0)
    elif not config.get("enable_port_scan", True):
        update_step("port_scan", status="skipped", message="Port scan disabled in settings.", progress=0)
        flags["port_scan_done"] = True
        save_state(state)
    else:
        update_step("port_scan", status="skipped", message="Port scan already completed.", progress=0)

    # ---------- httpx ----------
    httpx_processed: set = set()
    while True:
        state = load_state()
        tgt_state = ensure_target_state(state, domain)
        flags = tgt_state["flags"]
        submap = tgt_state["subdomains"]
        new_hosts = [
            host for host in sorted(submap.keys())
            if host not in httpx_processed and not (submap.get(host) or {}).get("httpx")
        ]
        for url in (tgt_state.get("web_urls") or []):
            if url and url not in httpx_processed and url not in new_hosts:
                new_hosts.append(url)
        if not flags.get("httpx_done") and not httpx_processed:
            log(f"=== httpx scan for {domain} ({len(submap)} hosts tracked) ===")
        if not new_hosts:
            if enumerators_done_event.is_set():
                flags["httpx_done"] = True
                save_state(state)
                update_step("httpx", status="completed", message="httpx scan finished.", progress=100)
                break
            job_sleep(job_domain, 5)
            continue
        update_step("httpx", status="running", message=f"httpx scanning {len(new_hosts)} pending hosts", progress=40)
        httpx_json = run_batch_sharded(
            "httpx", new_hosts, domain,
            lambda batch_file, suffix: httpx_scan(batch_file, domain, config=config,
                                                  job_domain=job_domain, out_suffix=suffix),
            config=config, job_domain=job_domain)
        if not httpx_json:
            job_log_append(job_domain, "httpx batch failed. Continuing with pipeline.", "httpx")
            update_step("httpx", status="error", message="httpx batch failed (timeouts or connection issues). Continuing with pipeline.", progress=100)
            # Don't break - httpx failures (especially timeouts) are common and shouldn't stop the pipeline
            # Mark these hosts as processed (failed) so we don't retry them indefinitely
            # and mark them as scanned to track the failure
            mark_hosts_scanned(state, domain, new_hosts, "httpx")
            httpx_processed.update(new_hosts)
            flags["httpx_done"] = True
            save_state(state)
            break
        else:
            enrich_state_with_httpx(state, domain, httpx_json)
            mark_hosts_scanned(state, domain, new_hosts, "httpx")
            httpx_processed.update(new_hosts)
            save_state(state)
            job_log_append(job_domain, f"httpx scanned {len(new_hosts)} hosts.", "httpx")
    
    # ---------- vhost enum (Host header brute on live web services) ----------
    state = load_state()
    tgt_state = ensure_target_state(state, domain)
    flags = tgt_state["flags"]
    vhost_urls = list(tgt_state.get("web_urls") or [])
    if not vhost_urls:
        for host, entry in (tgt_state.get("subdomains") or {}).items():
            httpx_info = (entry or {}).get("httpx") or {}
            url = httpx_info.get("url") or ""
            if url:
                vhost_urls.append(url)
            elif host:
                vhost_urls.append(f"http://{host}")
    if not flags.get("vhost_enum_done") and config.get("enable_vhost_enum", True):
        update_step("vhost_enum", status="running", message=f"vhost enum on {len(vhost_urls)} URLs", progress=40)
        discovered = vhost_enum_web_services(domain, vhost_urls, wordlist, config=config, job_domain=job_domain)
        state = load_state()
        add_subdomains_to_state(state, domain, discovered, "vhost")
        flags = ensure_target_state(state, domain)["flags"]
        flags["vhost_enum_done"] = True
        save_state(state)
        update_step("vhost_enum", status="completed", message=f"vhost enum found {len(discovered)} hosts.", progress=100)
        job_log_append(job_domain, f"vhost enum found {len(discovered)} hosts.", "vhost_enum")
    elif not config.get("enable_vhost_enum", True):
        update_step("vhost_enum", status="skipped", message="vhost enum disabled in settings.", progress=0)
        flags["vhost_enum_done"] = True
        save_state(state)
    else:
        update_step("vhost_enum", status="skipped", message="vhost enum already completed.", progress=0)
    # ---------- screenshots ----------
    if not config.get("enable_screenshots", True):
        state = load_state()
        flags = ensure_target_state(state, domain)["flags"]
        update_step("screenshots", status="skipped", message="Screenshots disabled in settings.", progress=0)
        flags["screenshots_done"] = True
        save_state(state)
    else:
        while True:
            state = load_state()
            tgt_state = ensure_target_state(state, domain)
            flags = tgt_state["flags"]
            screenshot_targets = gather_screenshot_targets(state, domain)
            if not screenshot_targets:
                if enumerators_done_event.is_set():
                    flags["screenshots_done"] = True
                    save_state(state)
                    update_step("screenshots", status="completed", message="Screenshot capture finished.", progress=100)
                    break
                job_sleep(job_domain, 5)
                continue
            update_step("screenshots", status="running", message=f"Capturing screenshots for {len(screenshot_targets)} hosts", progress=40)
            if job_domain:
                job_log_append(job_domain, "Waiting for screenshot slot...", "scheduler")
            with TOOL_GATES["gowitness"]:
                if job_domain:
                    job_log_append(job_domain, "Screenshot slot acquired.", "scheduler")
                screenshot_map = capture_screenshots(screenshot_targets, domain, config=config, job_domain=job_domain)
            if not screenshot_map:
                job_log_append(job_domain, "Screenshot batch failed.", "screenshots")
                update_step("screenshots", status="error", message="Screenshot capture failed.", progress=100)
                # Mark screenshot step as done on failure to prevent infinite retry
                # Record the failed attempt for hosts in this batch
                failed_hosts = [host for host, url in screenshot_targets]
                if failed_hosts:
                    mark_hosts_scanned(state, domain, failed_hosts, "screenshots")
                flags["screenshots_done"] = True
                save_state(state)
                break
            state = load_state()
            enrich_state_with_screenshots(state, domain, screenshot_map)
            save_state(state)
            job_log_append(job_domain, f"Captured screenshots for {len(screenshot_map)} hosts.", "screenshots")
            update_step("screenshots", status="running", message=f"Captured {len(screenshot_map)} screenshots. Waiting for new hosts…", progress=75)

    # ---------- nuclei ----------
    nuclei_processed: set = set()
    while True:
        state = load_state()
        tgt_state = ensure_target_state(state, domain)
        flags = tgt_state["flags"]
        submap = tgt_state["subdomains"]
        new_hosts = [
            host for host in sorted(submap.keys())
            if host not in nuclei_processed and not (submap.get(host) or {}).get("scans", {}).get("nuclei")
        ]
        if not flags.get("nuclei_done") and not nuclei_processed:
            log(f"=== nuclei scan for {domain} ({len(submap)} hosts tracked) ===")
        if not new_hosts:
            if enumerators_done_event.is_set():
                flags["nuclei_done"] = True
                save_state(state)
                update_step("nuclei", status="completed", message="nuclei scan finished.", progress=100)
                break
            job_sleep(job_domain, 5)
            continue
        update_step("nuclei", status="running", message=f"nuclei scanning {len(new_hosts)} pending hosts", progress=40)
        nuclei_json = run_batch_sharded(
            "nuclei", new_hosts, domain,
            lambda batch_file, suffix: nuclei_scan(batch_file, domain, config=config,
                                                   job_domain=job_domain, out_suffix=suffix),
            config=config, job_domain=job_domain)
        if not nuclei_json:
            job_log_append(job_domain, "nuclei batch failed.", "nuclei")
            update_step("nuclei", status="error", message="nuclei batch failed. Check logs for details.", progress=100)
            # Mark these hosts as processed (failed) so we don't retry them
            mark_hosts_scanned(state, domain, new_hosts, "nuclei")
            nuclei_processed.update(new_hosts)
            flags["nuclei_done"] = True
            save_state(state)
            break
        enrich_state_with_nuclei(state, domain, nuclei_json)
        mark_hosts_scanned(state, domain, new_hosts, "nuclei")
        nuclei_processed.update(new_hosts)
        save_state(state)
        job_log_append(job_domain, f"nuclei processed {len(new_hosts)} hosts.", "nuclei")

    state = load_state()
    flags = ensure_target_state(state, domain)["flags"]
    all_subs = sorted(ensure_target_state(state, domain)["subdomains"].keys())

    # ---------- JS gather & secret/endpoint scan ----------
    if not config.get("enable_js_scan", True):
        update_step("jsscan", status="skipped", message="JS scan disabled in settings.", progress=0)
        flags["js_scan_done"] = True
        save_state(state)
    elif flags.get("js_scan_done"):
        update_step("jsscan", status="skipped", message="JS scan already completed for this target.", progress=0)
    else:
        update_step("jsscan", status="running", message="Gathering & scanning JS assets…", progress=40)
        try:
            js_scan = run_js_scan(domain, config, job_domain=job_domain)
            s = js_scan.get("summary", {})
            update_step(
                "jsscan", status="completed",
                message=(f"JS scan: {s.get('secrets', 0)} secret(s), "
                         f"{s.get('endpoints', 0)} endpoint(s), {s.get('params', 0)} param(s) "
                         f"across {s.get('files_ok', 0)} file(s)."),
                progress=100,
            )
        except Exception as exc:
            log(f"JS scan failed for {domain}: {exc}")
            update_step("jsscan", status="error", message=f"JS scan failed: {exc}", progress=100)
        state = load_state()
        flags = ensure_target_state(state, domain)["flags"]
        flags["js_scan_done"] = True
        save_state(state)

    # ---------- nikto ----------
    if skip_nikto:
        update_step("nikto", status="skipped", message="Nikto skipped per run options.", progress=0)
    else:
        nikto_processed: set = set()
        while True:
            state = load_state()
            tgt_state = ensure_target_state(state, domain)
            flags = tgt_state["flags"]
            submap = tgt_state["subdomains"]
            new_hosts = [
                host for host in sorted(submap.keys())
                if host not in nikto_processed and not (submap.get(host) or {}).get("scans", {}).get("nikto")
            ]
            if not flags.get("nikto_done") and not nikto_processed:
                log(f"=== nikto scan for {domain} ({len(submap)} hosts tracked) ===")
            if not new_hosts:
                if enumerators_done_event.is_set():
                    flags["nikto_done"] = True
                    save_state(state)
                    update_step("nikto", status="completed", message="Nikto scan finished.", progress=100)
                    break
                job_sleep(job_domain, 5)
                continue
            update_step("nikto", status="running", message=f"Nikto scanning {len(new_hosts)} pending hosts", progress=40)
            nikto_json = nikto_scan(new_hosts, domain, config=config, job_domain=job_domain)
            if not nikto_json:
                job_log_append(job_domain, "Nikto batch failed.", "nikto")
                update_step("nikto", status="error", message="Nikto batch failed. Check logs for details.", progress=100)
                # Mark these hosts as processed (failed) so we don't retry them
                mark_hosts_scanned(state, domain, new_hosts, "nikto")
                nikto_processed.update(new_hosts)
                flags["nikto_done"] = True
                save_state(state)
                break
            enrich_state_with_nikto(state, domain, nikto_json)
            mark_hosts_scanned(state, domain, new_hosts, "nikto")
            nikto_processed.update(new_hosts)
            save_state(state)
            job_log_append(job_domain, f"Nikto scanned {len(new_hosts)} hosts.", "nikto")

    log("Pipeline finished for this run.")


def ffuf_bruteforce(
    domain: str,
    wordlist: str,
    config: Optional[Dict[str, Any]] = None,
    job_domain: Optional[str] = None,
) -> List[str]:
    """
    Use ffuf to brute-force vhosts via Host header.
    This is HTTP-based vhost brute, not pure DNS brute, but still useful.
    
    Only returns subdomains that are properly formatted as valid subdomains.
    ffuf is configured via -mc to only return specific status codes (200, 301, 302, 403, 401).
    """
    if not ensure_tool_installed("ffuf"):
        return []
    resolved = resolve_wordlist_path(wordlist)
    if not resolved or not Path(resolved).is_file():
        log(f"ffuf wordlist not found: {wordlist}")
        return []
    wordlist = resolved


    out_json = DATA_DIR / f"ffuf_{domain}.json"
    # NOTE: user can tune -mc, -fs, etc to avoid wildcard noise.
    # Removed -v flag to only log subdomains that match the status codes (not all attempts)
    cmd = [
        TOOLS["ffuf"],
        "-u", f"http://{domain}",
        "-H", "Host: FUZZ." + domain,
        "-w", wordlist,
        "-of", "json",
        "-o", str(out_json),
        "-mc", "200,301,302,403,401"
    ]
    context = {
        "DOMAIN": domain,
        "WORDLIST": wordlist,
        "OUTPUT": str(out_json),
        "TARGET_URL": f"http://{domain}",
        "HOST_HEADER": f"FUZZ.{domain}",
    }
    cmd = apply_template_flags("ffuf", cmd, context, config)
    success = run_subprocess(cmd, job_domain=job_domain, step="ffuf")
    if not success or not out_json.exists():
        return []

    subs = set()
    try:
        data = json.loads(out_json.read_text(encoding="utf-8"))
        invalid_count = 0
        for r in data.get("results", []):
            raw_host = r.get("host") or r.get("url")
            if raw_host:
                # ffuf may show host as FUZZ.domain.tld - clean and normalize it
                host = raw_host.replace("https://", "").replace("http://", "").split("/")[0].lower()
                
                # Validate subdomain format before adding
                # This filters out invalid entries from wordlist (comments, malformed names, etc.)
                if is_valid_subdomain(host):
                    subs.add(host)
                else:
                    invalid_count += 1
        
        if invalid_count > 0:
            msg = f"Filtered out {invalid_count} invalid subdomain entries from results"
            log(f"ffuf: {msg}")
            if job_domain:
                job_log_append(job_domain, msg, "ffuf")
    except Exception as e:
        log(f"Error parsing ffuf JSON: {e}")
    return sorted(subs)


def write_subdomains_file(domain: str, subs: List[str], suffix: Optional[str] = None) -> Path:
    sanitized = sorted(set(subs))
    out_name = f"subs_{domain}{suffix or ''}.txt"
    out_path = DATA_DIR / out_name
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for s in sanitized:
                f.write(s + "\n")
    except Exception as e:
        log(f"Error writing subdomains file: {e}")
    return out_path


def httpx_scan(subs_file: Path, domain: str, config: Optional[Dict[str, Any]] = None,
               job_domain: Optional[str] = None, out_suffix: str = "") -> Path:
    """
    Run httpx HTTP probing with enhanced error handling.
    
    Httpx may timeout on some hosts, which is normal - this shouldn't crash the pipeline.
    Returns the output JSON file path if successful, None otherwise.
    """
    if not ensure_tool_installed("httpx"):
        return None
    out_json = DATA_DIR / f"httpx_{domain}{out_suffix}.json"
    cmd = [
        TOOLS["httpx"],
        "-l", str(subs_file),
        "-json",
        "-o", str(out_json),
        "-timeout", "10",
        "-follow-redirects",
        "-title",         # Extract page titles
        "-tech-detect",   # Detect technologies  
        "-status-code",   # Show status codes
        "-server",        # Extract server headers
        "-v",
    ]
    context = {
        "DOMAIN": domain,
        "INPUT_FILE": str(subs_file),
        "OUTPUT": str(out_json),
    }
    cmd = apply_template_flags("httpx", cmd, context, config)
    
    # Run httpx - it may fail on individual hosts (timeouts) but should still produce output
    success = run_subprocess(cmd, job_domain=job_domain, step="httpx")
    
    # Even if httpx returns non-zero exit code (some hosts timed out),
    # it may have successfully probed other hosts and written partial results
    # So check if output file exists with content, not just success flag
    if out_json.exists() and out_json.stat().st_size > 0:
        return out_json
    elif success:
        # Success but no output - probably no hosts responded
        if job_domain:
            job_log_append(job_domain, "httpx completed but found no responsive hosts", "httpx")
        return None
    else:
        # Failed and no output
        return None


def _merge_jsonl_files(parts: List[Path], destination: Path) -> Optional[Path]:
    """Concatenate JSONL shard outputs into one file and drop the shards."""
    written = 0
    try:
        with open(destination, "w", encoding="utf-8") as out_handle:
            for part in parts:
                if not part or not part.exists():
                    continue
                with open(part, "r", encoding="utf-8", errors="replace") as in_handle:
                    for line in in_handle:
                        line = line.strip()
                        if line:
                            out_handle.write(line + "\n")
                            written += 1
    except Exception as exc:
        log(f"Failed merging shard output into {destination.name}: {exc}")
        return None
    for part in parts:
        try:
            if part and part.exists():
                part.unlink()
        except Exception:
            pass
    return destination if written else None
