"""Fragment 13_save_all_api_keys.py. Loaded into the main module namespace."""
# ================== PIPELINE STEPS ==================

def run_subprocess(
    cmd,
    outfile: Optional[Path] = None,
    *,
    job_domain: Optional[str] = None,
    step: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
) -> bool:
    # Apply global rate limiting before running any tool
    apply_rate_limit()
    
    display_cmd = " ".join(cmd)
    log(f"Running: {display_cmd}")
    if job_domain:
        job_pause_point(job_domain)
    if job_domain:
        job_log_append(job_domain, f"$ {display_cmd}", source=step or "command")
    try:
        merged_env = os.environ.copy()
        
        # Set environment variables to prevent interactive prompts from various tools
        # These ensure tools run in non-interactive mode and don't freeze waiting for input
        non_interactive_env = {
            "DEBIAN_FRONTEND": "noninteractive",
            "TERM": "dumb",
            "CI": "true",
            "NUCLEI_NONINTERACTIVE": "1",
            "NUCLEI_NO_COLOR": "1",
            "NO_COLOR": "1",
            "PAGER": "",
            "MANPAGER": "",
        }
        
        # Apply non-interactive environment
        merged_env.update(non_interactive_env)
        
        # Apply any custom environment variables passed in
        if env:
            merged_env.update({k: str(v) for k, v in env.items()})

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=merged_env,
            timeout=timeout,
            stdin=subprocess.DEVNULL,  # Prevent reading from stdin - critical for non-interactive mode
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if outfile:
            try:
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(stdout)
            except Exception as file_err:
                log(f"Error writing {outfile}: {file_err}")

        if job_domain:
            if stdout.strip():
                job_log_append(job_domain, stdout, source=step or cmd[0])
            if stderr.strip():
                job_log_append(job_domain, stderr, source=f"{(step or cmd[0]).upper()} stderr")

        if result.returncode != 0:
            stderr_preview = (stderr or "")[:500]
            log(
                f"Command failed (return code {result.returncode}): "
                + display_cmd
                + "\nstderr: " + stderr_preview
            )
            
            # Check if stderr contains rate limit indicators and track them
            combined_output = stdout + stderr
            if any(keyword in combined_output.lower() for keyword in 
                   ["rate limit", "too many requests", "429", "throttle", "slow down"]):
                if job_domain:
                    track_timeout_error(job_domain, Exception(stderr_preview), job_domain)
            
            return False

    except subprocess.TimeoutExpired as e:
        log(f"Command timeout: {display_cmd}")
        if job_domain:
            job_log_append(job_domain, f"Command timeout after {timeout}s", source=step or "system")
            # Track timeout errors
            track_timeout_error(job_domain, e, job_domain)
        return False

    except FileNotFoundError:
        log(f"Command not found: {cmd[0]}")
        if job_domain:
            job_log_append(job_domain, f"Command not found: {cmd[0]}", source=step or "system")
        return False

    except Exception as e:
        log("Error running command " + display_cmd + f": {e}")
        if job_domain:
            job_log_append(job_domain, f"Error: {e}", source=step or "system")
            # Track potential rate limit errors
            track_timeout_error(job_domain, e, job_domain)
        return False

    return True


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape sequences (color codes, formatting) from text.
    This handles common terminal color codes that tools like sublist3r add to output.
    """
    # Pattern matches ANSI escape sequences including CSI sequences
    # \x1b is ESC (hex), \033 is ESC (octal)
    # Matches standard ANSI control sequences ending in A-Za-z
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\033\[[0-9;]*[A-Za-z]')
    return ansi_escape.sub('', text)


def is_valid_subdomain(text: str) -> bool:
    """
    Validate that a string looks like a valid domain or subdomain.
    Returns False for ANSI codes, error messages, status messages, wildcards, etc.
    
    NOTE: This function is used to validate tool output (discovered subdomains).
    Wildcards are rejected here because tools should return concrete subdomains,
    not wildcard patterns. Wildcard inputs are handled separately by expand_wildcard_targets().
    """
    if not text:
        return False
    
    # Strip ANSI codes first
    cleaned = strip_ansi_codes(text).strip()
    if not cleaned:
        return False
    
    # Reject wildcards - these should not appear in tool output
    # Wildcard DNS records like *.api.example.com should be ignored
    if '*' in cleaned:
        return False
    
    # Reject lines that are clearly not domains
    # Check for common patterns in tool output that shouldn't be domains
    invalid_patterns = [
        r'^\[',  # Starts with bracket (ANSI remnants, arrays, etc.)
        r'^\]',  # Starts with closing bracket
        r'^[-\+#]',  # Starts with status symbols
        r'error|Error|ERROR',  # Contains error keywords
        r'warning|Warning|WARNING',  # Contains warning keywords
        r'searching|enumerat|finish|coded by',  # Tool status messages
        r'^\s*$',  # Empty or whitespace only
        r'\s{2,}',  # Multiple consecutive spaces (likely formatted output)
        r'^[0-9]+\s',  # Starts with number and space (table rows)
        r'^\||^-+$|^\++$',  # Table borders
        r'^http://|^https://',  # URLs (not raw domains)
        r'[ \t\r\n\f\v]',  # Contains ASCII whitespace (domains don't have spaces)
    ]
    
    for pattern in invalid_patterns:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return False
    
    # Basic domain validation: should contain at least one dot and valid chars
    # Valid domain characters: alphanumeric, dots, hyphens, underscores
    # Must contain at least one dot (subdomain.domain or domain.tld)
    if '.' not in cleaned:
        return False
    
    # Check if it looks like a domain (alphanumeric with dots, hyphens, underscores)
    # No wildcards allowed in tool output
    domain_pattern = r'^[a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+$'
    if not re.match(domain_pattern, cleaned, re.IGNORECASE):
        return False
    
    return True


def read_lines_file(path: Path) -> List[str]:
    if not path or not path.exists():
        return []
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    # Strip ANSI codes and validate
                    cleaned = strip_ansi_codes(line).strip()
                    if cleaned and is_valid_subdomain(cleaned):
                        lines.append(cleaned.lower())
    except Exception as exc:
        log(f"Error reading {path}: {exc}")
    return lines



