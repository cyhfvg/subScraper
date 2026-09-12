"""Fragment 10_save_state.py. Loaded into the main module namespace."""
def save_state(state: Dict[str, Any]) -> None:
    """Save state (targets and subdomains) to SQLite database."""
    now = datetime.now(timezone.utc).isoformat()
    state["last_updated"] = now
    
    acquire_lock()
    try:
        db = get_db()
        cursor = db.cursor()
        
        targets = state.get("targets", {})
        
        for domain, target_data in targets.items():
            subdomains = target_data.get("subdomains", {})
            flags = target_data.get("flags", {})
            options = target_data.get("options", {})
            target_comments = target_data.get("comments", [])
            # Everything else on the target (endpoints, js_scan, ...) goes to targets.data
            # so it survives the round-trip through the database.
            extra = {key: value for key, value in target_data.items()
                     if key not in ("subdomains", "flags", "options", "comments")}
            
            # Insert or update target
            cursor.execute(
                """INSERT INTO targets (domain, data, flags, options, comments, created_at, updated_at) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(domain) DO UPDATE SET 
                   data = excluded.data,
                   flags = excluded.flags,
                   options = excluded.options,
                   comments = excluded.comments,
                   updated_at = excluded.updated_at""",
                (domain, json.dumps(extra), json.dumps(flags), json.dumps(options),
                 json.dumps(target_comments), now, now)
            )
            
            # Delete old subdomains not in current state
            current_subdomains = set(subdomains.keys())
            cursor.execute(
                "SELECT subdomain FROM subdomains WHERE domain = ?",
                (domain,)
            )
            existing_subdomains = {row[0] for row in cursor.fetchall()}
            
            for old_subdomain in existing_subdomains - current_subdomains:
                cursor.execute(
                    "DELETE FROM subdomains WHERE domain = ? AND subdomain = ?",
                    (domain, old_subdomain)
                )
            
            # Insert or update subdomains
            for subdomain, sub_data in subdomains.items():
                # Extract interesting and comments from sub_data
                interesting = sub_data.get("interesting")
                interesting_val = None if interesting is None else (1 if interesting else 0)
                comments_data = sub_data.get("comments", [])
                
                # Create clean sub_data without interesting/comments for data field
                clean_sub_data = {k: v for k, v in sub_data.items() if k not in ("interesting", "comments")}
                
                cursor.execute(
                    """INSERT INTO subdomains (domain, subdomain, data, interesting, comments, created_at, updated_at) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(domain, subdomain) DO UPDATE SET 
                       data = excluded.data,
                       interesting = excluded.interesting,
                       comments = excluded.comments,
                       updated_at = excluded.updated_at""",
                    (domain, subdomain, json.dumps(clean_sub_data), interesting_val, json.dumps(comments_data), now, now)
                )
        
        db.commit()
        
        # Invalidate state cache after successful save
        invalidate_state_cache()
    finally:
        release_lock()
    
    try:
        generate_html_dashboard(state)
    except Exception as e:
        log(f"Error refreshing dashboard HTML: {e}")



def load_completed_jobs() -> Dict[str, Dict[str, Any]]:
    """Load completed jobs from SQLite database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT job_key, data FROM completed_jobs")
    rows = cursor.fetchall()
    
    jobs = {}
    for row in rows:
        job_key = row[0]
        try:
            job_data = json.loads(row[1])
            jobs[job_key] = job_data
        except json.JSONDecodeError:
            pass
    
    return jobs


def save_completed_jobs() -> None:
    """Save completed jobs to SQLite database."""
    with JOB_LOCK:
        jobs_to_save = copy.deepcopy(COMPLETED_JOBS)
    
    try:
        db = get_db()
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        for job_key, job_data in jobs_to_save.items():
            domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
            completed_at = job_data.get("completed_at", now)
            
            cursor.execute(
                """INSERT OR REPLACE INTO completed_jobs 
                   (job_key, domain, data, completed_at, created_at) 
                   VALUES (?, ?, ?, ?, ?)""",
                (job_key, domain, json.dumps(job_data), completed_at, now)
            )
        
        db.commit()
    except Exception as e:
        log(f"Error saving completed jobs: {e}")


def add_completed_job(domain: str, job_data: Dict[str, Any]) -> None:
    """
    Add a completed job to the completed jobs storage.
    Keeps only the last MAX_COMPLETED_JOBS_PER_DOMAIN jobs per domain.
    """
    with JOB_LOCK:
        # Remove thread reference before deepcopy as it's not serializable
        # Thread objects contain locks that cannot be pickled
        job_data_copy = {k: v for k, v in job_data.items() if k != 'thread'}
        job_copy = copy.deepcopy(job_data_copy)
        
        # Add completion timestamp
        completion_time = datetime.now(timezone.utc)
        job_copy["completed_at"] = completion_time.isoformat()
        
        # Store with a unique key that includes high-precision timestamp to allow multiple runs
        # Using timestamp() gives microsecond precision to avoid collisions
        job_key = f"{domain}_{completion_time.timestamp()}"
        COMPLETED_JOBS[job_key] = job_copy
        
        # Cleanup old completed jobs for this domain
        domain_jobs = [(k, v) for k, v in COMPLETED_JOBS.items() if k.startswith(f"{domain}_")]
        if len(domain_jobs) > MAX_COMPLETED_JOBS_PER_DOMAIN:
            # Sort by completion time and keep only the most recent
            domain_jobs.sort(key=lambda x: x[1].get("completed_at", ""), reverse=True)
            for old_key, _ in domain_jobs[MAX_COMPLETED_JOBS_PER_DOMAIN:]:
                COMPLETED_JOBS.pop(old_key, None)
    
    # Save to disk
    save_completed_jobs()


# Resolving a tool means stat()ing candidate paths and, for httpx and nuclei,
# running the binary with -version to make sure it is the right project's tool.
# The dashboard asks for tool status on every poll, so the answer is cached.
TOOL_PATH_CACHE: Dict[str, Tuple[float, Optional[str]]] = {}
TOOL_PATH_CACHE_LOCK = threading.Lock()
TOOL_PATH_CACHE_TTL = 300.0  # seconds


def invalidate_tool_path_cache(tool: Optional[str] = None) -> None:
    """Drop cached tool locations after an install, or when asked to re-check."""
    with TOOL_PATH_CACHE_LOCK:
        if tool:
            TOOL_PATH_CACHE.pop(tool, None)
        else:
            TOOL_PATH_CACHE.clear()


def resolve_tool_path_cached(tool: str, max_age: Optional[float] = None) -> Optional[str]:
    """Cached _resolve_tool_path() for the polling paths (state payload, UI)."""
    ttl = TOOL_PATH_CACHE_TTL if max_age is None else max_age
    now = time.time()
    with TOOL_PATH_CACHE_LOCK:
        cached = TOOL_PATH_CACHE.get(tool)
        if cached and (now - cached[0]) < ttl:
            return cached[1]
    resolved = _resolve_tool_path(tool)
    with TOOL_PATH_CACHE_LOCK:
        TOOL_PATH_CACHE[tool] = (time.time(), resolved)
    return resolved


def _running_on_windows() -> bool:
    """Single place to ask "is this Windows?" so tests can simulate it."""
    return os.name == "nt"


def _candidate_tool_paths(exe: str) -> List[str]:
    """
    Return a de-duplicated list of candidate paths for a tool, checking PATH and common Go bin dirs.
    """
    candidates: List[str] = []
    exe_path = Path(exe)
    if exe_path.is_absolute():
        candidates.append(str(exe_path))
    else:
        found = shutil.which(exe)
        if found:
            candidates.append(found)
    # On Windows the binary carries an extension; shutil.which() knows about
    # PATHEXT but the Go bin directories below have to be checked explicitly.
    windows = _running_on_windows()
    names = [exe]
    if windows and not exe.lower().endswith((".exe", ".bat", ".cmd")):
        names = [exe + ".exe", exe + ".bat", exe + ".cmd", exe]
    bin_dirs: List[Path] = []
    gobin = os.environ.get("GOBIN")
    if gobin:
        bin_dirs.append(Path(gobin))
    gopath = os.environ.get("GOPATH")
    if gopath:
        bin_dirs.append(Path(gopath) / "bin")
    bin_dirs.append(Path.home() / "go" / "bin")
    if windows:
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            bin_dirs.append(Path(local_app) / "Microsoft" / "WinGet" / "Links")
        bin_dirs.append(Path.home() / "scoop" / "shims")
    else:
        bin_dirs.extend([Path("/usr/local/bin"), Path("/opt/homebrew/bin"), Path("/snap/bin"),
                         Path.home() / ".local" / "bin", Path.home() / ".cargo" / "bin"])
    for bin_dir in bin_dirs:
        for name in names:
            candidates.append(str(bin_dir / name))
    seen = set()
    ordered: List[str] = []
    for cand in candidates:
        if not cand:
            continue
        if cand in seen:
            continue
        seen.add(cand)
        ordered.append(cand)
    return ordered


def _validate_tool_binary(tool: str, path_str: str) -> bool:
    """
    Ensure we are invoking the intended binary.
    This is mainly to avoid grabbing the Python 'httpx' CLI instead of ProjectDiscovery's tool.
    """
    if not path_str:
        return False
    path = Path(path_str)
    if not path.exists():
        return False
    if tool not in {"httpx", "nuclei"}:
        return True
    try:
        result = subprocess.run(
            [str(path), "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception:
        return False
    output = (result.stdout or "") + (result.stderr or "")
    output_lower = output.lower()
    if tool == "httpx":
        if "projectdiscovery" in output_lower or "httpx version" in output_lower:
            return True
        if "httpx command line client" in output_lower:
            return False
    elif tool == "nuclei":
        if "nuclei engine version" in output_lower or "projectdiscovery" in output_lower:
            return True
    return False


def _resolve_tool_path(tool: str) -> Optional[str]:
    """
    Resolve the path to a tool binary, checking custom paths first,
    then standard locations.
    """
    # Check custom binary paths from config first
    config = get_config()
    custom_paths = config.get("tool_binary_paths", {})
    if tool in custom_paths:
        custom_path = custom_paths[tool]
        if custom_path and Path(custom_path).exists():
            if _validate_tool_binary(tool, custom_path):
                log(f"Using custom binary path for {tool}: {custom_path}")
                return custom_path
            else:
                log(f"Custom path for {tool} at {custom_path} failed validation. Trying standard locations.")
    
    # Fall back to standard tool resolution
    exe = TOOLS[tool]
    candidates = _candidate_tool_paths(exe)
    for cand in candidates:
        if not cand:
            continue
        path = Path(cand)
        if not path.exists():
            continue
        if _validate_tool_binary(tool, cand):
            return cand
        else:
            log(f"Found {tool} at {cand} but it does not look like the expected binary. Ignoring.")
    return None


# ================== PLATFORM DETECTION & TOOL INSTALLATION ==================

# Package name per tool, per package manager. A tool only gets an install
# method here when that manager genuinely ships it - a wrong package name is
# worse than no suggestion, because it sends people down a dead end.
#
# Deliberate omissions:
#   - httpx via apt/pip installs the *Python* httpx CLI, not ProjectDiscovery's.
#   - nikto/github-subdomains have no trustworthy Windows package.
TOOL_PACKAGES: Dict[str, Dict[str, str]] = {
    "dnsx": {"apt": "dnsx", "brew": "dnsx",
             "go": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    "nmap": {"apt": "nmap", "dnf": "nmap", "yum": "nmap", "pacman": "nmap",
             "zypper": "nmap", "apk": "nmap", "brew": "nmap", "choco": "nmap"},
    "ffuf": {"apt": "ffuf", "brew": "ffuf", "pacman": "ffuf", "dnf": "ffuf",
             "go": "github.com/ffuf/ffuf/v2@latest"},
    "httpx": {"go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "nuclei": {"apt": "nuclei", "brew": "nuclei", "pacman": "nuclei",
               "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "nikto": {"apt": "nikto", "brew": "nikto", "dnf": "nikto", "pacman": "nikto"},
    "gowitness": {"apt": "gowitness", "brew": "gowitness",
                  "go": "github.com/sensepost/gowitness@latest"},
}

TOOL_DOCS = {
    "dnsx": "https://github.com/projectdiscovery/dnsx",
    "nmap": "https://nmap.org",
    "ffuf": "https://github.com/ffuf/ffuf",
    "httpx": "https://github.com/projectdiscovery/httpx",
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "nikto": "https://github.com/sullo/nikto",
    "gowitness": "https://github.com/sensepost/gowitness",
}

TOOL_NOTES = {
    "nikto": "Needs Perl and XML::Writer (apt: libxml-writer-perl; cpan XML::Writer). On Windows install Strawberry Perl, then run nikto.pl from a clone of the repo.",
    "gowitness": "Needs Chrome or Chromium installed for screenshots.",
    "httpx": ("Must be ProjectDiscovery's httpx. The Python package and Homebrew's core 'httpx' "
              "formula are a different tool and are rejected on purpose - install with go, or "
              "'brew install projectdiscovery/tap/httpx'."),
    "nmap": "Used for intranet port scan and service detection. Install via the OS package manager.",
    "dnsx": "Intranet DNS brute and live-host verification. Provide a wordlist and local resolvers.",
}

# Managers that need root on Unix. brew refuses to run as root by design.
_ROOT_MANAGERS = {"apt", "dnf", "yum", "zypper", "pacman", "apk", "snap", "port", "choco"}

_PLATFORM_CACHE: Dict[str, Any] = {}
_PKG_AVAILABILITY_CACHE: Dict[Tuple[str, str], bool] = {}
_APT_UPDATED = False


def _which(name: str) -> Optional[str]:
    try:
        return shutil.which(name)
    except Exception:
        return None


def _read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                for line in handle:
                    if "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    data[key.strip()] = value.strip().strip('"').strip("'")
            if data:
                break
        except Exception:
            continue
    return data


def _distro_family(os_release: Dict[str, str]) -> str:
    ident = (os_release.get("ID") or "").lower()
    like = (os_release.get("ID_LIKE") or "").lower().split()
    names = [ident] + like
    for name in names:
        if name in ("debian", "ubuntu", "kali", "raspbian", "linuxmint", "pop"):
            return "debian"
        if name in ("rhel", "fedora", "centos", "rocky", "almalinux", "amzn"):
            return "rhel"
        if name in ("arch", "manjaro", "endeavouros"):
            return "arch"
        if name in ("suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"):
            return "suse"
        if name == "alpine":
            return "alpine"
    return "unknown"
