"""Fragment 18_nikto_scan_hosts.py. Loaded into the main module namespace."""
def _nikto_scan_hosts(subs: List[str], domain: str, config: Optional[Dict[str, Any]] = None,
                      job_domain: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan one slice of hosts with nikto, sequentially, returning its findings."""
    results: List[Dict[str, Any]] = []
    out_json = DATA_DIR / f"nikto_{domain}.json"
    for host in subs:
        target = f"http://{host}"
        cmd = [
            TOOLS["nikto"],
            "-h", target,
        ]
        context = {
            "DOMAIN": domain,
            "SUBDOMAIN": host,
            "TARGET_URL": target,
            "OUTPUT": str(out_json),
        }
        cmd = apply_template_flags("nikto", cmd, context, config)
        log(f"Running nikto against {target}")
        if job_domain:
            job_log_append(job_domain, f"Nikto scanning {target}", source="nikto")
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            log("Nikto binary not found during run.")
            return results
        except Exception as e:
            log(f"Nikto error for {host}: {e}")
            if job_domain:
                job_log_append(job_domain, f"Nikto error for {host}: {e}", source="nikto")
            continue

        stdout_text = proc.stdout or ""
        stderr_text = proc.stderr or ""
        if job_domain and stdout_text:
            job_log_append(job_domain, stdout_text, source="nikto")
        if job_domain and stderr_text:
            job_log_append(job_domain, stderr_text, source="nikto stderr")

        host_findings = _parse_nikto_output(host, stdout_text)
        if host_findings:
            results.extend(host_findings)
        if proc.returncode != 0 and not host_findings:
            log(f"Nikto failed for {host}: {stderr_text[:300]}")
            continue

    return results


# ================== STATE ENRICHMENT ==================


def make_subdomain_entry() -> Dict[str, Any]:
    return {
        "sources": [],
        "httpx": None,
        "nuclei": [],
        "nikto": [],
        "screenshot": None,
        "scans": {},
    }


def ensure_target_state(state: Dict[str, Any], domain: str) -> Dict[str, Any]:
    targets = state.setdefault("targets", {})
    tgt = targets.setdefault(domain, {
        "subdomains": {},
        "endpoints": [],  # Store discovered URLs from waybackurls and gau
        "flags": {
            "amass_done": False,
            "subfinder_done": False,
            "assetfinder_done": False,
            "findomain_done": False,
            "sublist3r_done": False,
            "ffuf_done": False,
            "httpx_done": False,
            "screenshots_done": False,
            "nuclei_done": False,
            "js_scan_done": False,
            "nikto_done": False,
        }
    })
    # Normalize missing keys
    tgt.setdefault("subdomains", {})
    tgt.setdefault("endpoints", [])
    tgt.setdefault("flags", {})
    tgt.setdefault("options", {})
    for k in ["amass_done", "subfinder_done", "assetfinder_done", "findomain_done", "sublist3r_done",
              "ffuf_done", "httpx_done", "screenshots_done", "nuclei_done", "js_scan_done", "nikto_done"]:
        tgt["flags"].setdefault(k, False)
    for sub, entry in list(tgt["subdomains"].items()):
        if not isinstance(entry, dict):
            tgt["subdomains"][sub] = make_subdomain_entry()
            continue
        entry.setdefault("sources", [])
        entry.setdefault("httpx", None)
        entry.setdefault("nuclei", [])
        entry.setdefault("nikto", [])
        entry.setdefault("screenshot", None)
        entry.setdefault("scans", {})
    return tgt


def add_subdomains_to_state(state: Dict[str, Any], domain: str, subs: List[str], source: str) -> None:
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    for s in subs:
        s = s.strip().lower()
        if not s:
            continue
        entry = submap.setdefault(s, make_subdomain_entry())
        entry.setdefault("sources", [])
        entry.setdefault("screenshot", None)
        entry.setdefault("scans", {})
        if source not in entry["sources"]:
            entry["sources"].append(source)


def enrich_state_with_httpx(state: Dict[str, Any], domain: str, httpx_json: Path) -> None:
    if not httpx_json or not httpx_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        with open(httpx_json, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                host = obj.get("host") or obj.get("url")
                if not host:
                    continue
                host = host.replace("https://", "").replace("http://", "").split("/")[0].lower()
                entry = submap.setdefault(host, make_subdomain_entry())
                entry.setdefault("screenshot", None)
                entry.setdefault("scans", {})
                entry["httpx"] = {
                    "url": obj.get("url"),
                    "status_code": obj.get("status_code"),
                    "content_length": obj.get("content_length"),
                    "title": obj.get("title"),
                    "webserver": obj.get("webserver"),
                    "tech": obj.get("tech"),
                }
    except Exception as e:
        log(f"Error enriching state with httpx data: {e}")


def enrich_state_with_nuclei(state: Dict[str, Any], domain: str, nuclei_json: Path) -> None:
    if not nuclei_json or not nuclei_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        with open(nuclei_json, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                host = obj.get("host") or obj.get("matched-at") or obj.get("url")
                if not host:
                    continue
                host = host.replace("https://", "").replace("http://", "").split("/")[0].lower()
                entry = submap.setdefault(host, make_subdomain_entry())
                entry.setdefault("screenshot", None)
                entry.setdefault("scans", {})
                finding = {
                    "template_id": obj.get("template-id"),
                    "name": (obj.get("info") or {}).get("name"),
                    "severity": (obj.get("info") or {}).get("severity"),
                    "matched_at": obj.get("matched-at") or obj.get("url"),
                }
                entry.setdefault("nuclei", []).append(finding)
    except Exception as e:
        log(f"Error enriching state with nuclei data: {e}")


def enrich_state_with_nikto(state: Dict[str, Any], domain: str, nikto_json: Path) -> None:
    if not nikto_json or not nikto_json.exists():
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    try:
        data = json.loads(nikto_json.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            data = [data]
        for obj in data:
            host = obj.get("host") or obj.get("target") or obj.get("banner")
            if not host:
                continue
            host = str(host).replace("https://", "").replace("http://", "").split("/")[0].lower()
            entry = submap.setdefault(host, make_subdomain_entry())
            entry.setdefault("screenshot", None)
            entry.setdefault("scans", {})
            vulns = obj.get("vulnerabilities") or obj.get("vulns")
            if not vulns:
                vulns = [obj]
            normalized_vulns = []
            for v in vulns:
                if isinstance(v, dict):
                    normalized_vulns.append({
                        "id": v.get("id"),
                        "msg": v.get("msg") or v.get("description") or v.get("message"),
                        "osvdb": v.get("osvdb"),
                        "risk": v.get("risk"),
                        "uri": v.get("uri"),
                        "severity": _normalize_nikto_severity(v.get("risk"), v.get("msg") or v.get("description") or v.get("message")),
                    })
                else:
                    normalized_vulns.append({"raw": str(v), "severity": _normalize_nikto_severity(None, str(v))})
            entry.setdefault("nikto", []).extend(normalized_vulns)
    except Exception as e:
        log(f"Error enriching state with nikto data: {e}")


def enrich_state_with_screenshots(state: Dict[str, Any], domain: str, mapping: Dict[str, Dict[str, Any]]) -> None:
    if not mapping:
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    for host, data in mapping.items():
        entry = submap.setdefault(host, make_subdomain_entry())
        entry.setdefault("scans", {})
        entry["screenshot"] = data


def mark_hosts_scanned(state: Dict[str, Any], domain: str, hosts: List[str], step: str) -> None:
    if not hosts:
        return
    tgt = ensure_target_state(state, domain)
    submap = tgt["subdomains"]
    timestamp = datetime.now(timezone.utc).isoformat()
    for host in hosts:
        host_norm = (host or "").strip().lower()
        if not host_norm:
            continue
        entry = submap.setdefault(host_norm, make_subdomain_entry())
        scans = entry.setdefault("scans", {})
        scans[step] = timestamp


def target_has_pending_work(target: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> bool:
    flags = target.get("flags", {})
    if any(not bool(value) for value in flags.values()):
        return True
    submap = target.get("subdomains", {})
    enable_screenshots = True if config is None else config.get("enable_screenshots", True)
    options = target.get("options", {}) or {}
    skip_nikto = options.get("skip_nikto")
    if skip_nikto is None and config is not None:
        skip_nikto = bool(config.get("skip_nikto_by_default", False))
    else:
        skip_nikto = bool(skip_nikto)
    for entry in submap.values():
        if not isinstance(entry, dict):
            return True
        scans = entry.get("scans") or {}
        if not entry.get("httpx"):
            return True
        if enable_screenshots and entry.get("httpx") and not entry.get("screenshot"):
            return True
        if not scans.get("nuclei"):
            return True
        if not skip_nikto and not scans.get("nikto"):
            return True
    return False


# ================== DASHBOARD GENERATION ==================

def generate_html_dashboard(state: Optional[Dict[str, Any]] = None) -> None:
    """
    Generate a single HTML file from the global state.
    All runs of this script share this dashboard.
    """
    if state is None:
        state = load_state()
    targets = state.get("targets", {})

    # Very simple HTML; auto-refresh via meta
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        f"<meta http-equiv='refresh' content='{HTML_REFRESH_SECONDS}'>",
        "<title>Recon Dashboard</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; padding: 20px; }",
        "h1 { color:#facc15; }",
        "h2 { color:#93c5fd; }",
        "table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }",
        "th, td { border: 1px solid #1f2937; padding: 4px 6px; font-size: 12px; }",
        "th { background:#111827; }",
        "tr:nth-child(even) { background:#020617; }",
        ".tag { display:inline-block; padding:2px 6px; border-radius:999px; margin-right:4px; font-size:10px; }",
        ".sev-low { background:#0f766e; }",
        ".sev-medium { background:#eab308; }",
        ".sev-high { background:#f97316; }",
        ".sev-critical { background:#b91c1c; }",
        ".badge { background:#1f2937; padding:2px 6px; border-radius:999px; font-size:11px; margin-right:4px; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Recon Dashboard</h1>",
        f"<p>Last updated: {state.get('last_updated', 'never')}</p>",
    ]

    for domain, tgt in sorted(targets.items(), key=lambda x: x[0]):
        subs = tgt.get("subdomains", {})
        flags = tgt.get("flags", {})
        html_parts.append(f"<h2>{domain}</h2>")
        html_parts.append(
            "<p>"
            f"<span class='badge'>Subdomains: {len(subs)}</span>"
            f"<span class='badge'>Amass: {'✅' if flags.get('amass_done') else '⏳'}</span>"
            f"<span class='badge'>Subfinder: {'✅' if flags.get('subfinder_done') else '⏳'}</span>"
            f"<span class='badge'>Assetfinder: {'✅' if flags.get('assetfinder_done') else '⏳'}</span>"
            f"<span class='badge'>Findomain: {'✅' if flags.get('findomain_done') else '⏳'}</span>"
            f"<span class='badge'>Sublist3r: {'✅' if flags.get('sublist3r_done') else '⏳'}</span>"
            f"<span class='badge'>ffuf: {'✅' if flags.get('ffuf_done') else '⏳'}</span>"
            f"<span class='badge'>httpx: {'✅' if flags.get('httpx_done') else '⏳'}</span>"
            f"<span class='badge'>Screenshots: {'✅' if flags.get('screenshots_done') else '⏳'}</span>"
            f"<span class='badge'>nuclei: {'✅' if flags.get('nuclei_done') else '⏳'}</span>"
            f"<span class='badge'>nikto: {'✅' if flags.get('nikto_done') else '⏳'}</span>"
            "</p>"
        )

        html_parts.append("<table>")
        html_parts.append(
            "<tr>"
            "<th>#</th>"
            "<th>Subdomain</th>"
            "<th>Sources</th>"
            "<th>HTTP</th>"
            "<th>Screenshot</th>"
            "<th>Nuclei Findings</th>"
            "<th>Nikto Findings</th>"
            "</tr>"
        )
        for idx, (sub, info) in enumerate(sorted(subs.items(), key=lambda x: x[0]), start=1):
            sources = info.get("sources", [])
            httpx = info.get("httpx") or {}
            screenshot = info.get("screenshot") or {}
            nuclei = info.get("nuclei") or []
            nikto = info.get("nikto") or []

            # HTTP summary
            http_summary = ""
            if httpx:
                http_summary = (
                    f"{httpx.get('status_code')} "
                    f"{httpx.get('title') or ''} "
                    f"[{httpx.get('webserver') or ''}]"
                )

            # Nuclei summary
            nuclei_bits = []
            for n in nuclei:
                sev = (n.get("severity") or "info").lower()
                cls = "sev-" + ("critical" if sev == "critical"
                                else "high" if sev == "high"
                                else "medium" if sev == "medium"
                                else "low")
                nuclei_bits.append(
                    f"<span class='tag {cls}'>{sev}: {n.get('template_id')}</span>"
                )
            nuclei_html = " ".join(nuclei_bits)

            # Nikto summary
            nikto_html = ""
            if nikto:
                nikto_html = f"{len(nikto)} findings"

            screenshot_html = ""
            screenshot_path = screenshot.get("path")
            if screenshot_path:
                screenshot_html = (
                    f"<a href='/screenshots/{screenshot_path}' target='_blank'>View</a>"
                )

            html_parts.append(
                "<tr>"
                f"<td>{idx}</td>"
                f"<td>{sub}</td>"
                f"<td>{', '.join(sources)}</td>"
                f"<td>{http_summary}</td>"
                f"<td>{screenshot_html or '—'}</td>"
                f"<td>{nuclei_html}</td>"
                f"<td>{nikto_html}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    html_parts.append("</body></html>")

    acquire_lock()
    try:
        atomic_write_text(HTML_DASHBOARD_FILE, "\n".join(html_parts))
    finally:
        release_lock()
