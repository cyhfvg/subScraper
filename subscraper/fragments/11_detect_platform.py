"""Fragment 11_detect_platform.py. Loaded into the main module namespace."""
def detect_platform(refresh: bool = False) -> Dict[str, Any]:
    """
    Detect OS, distribution and the package managers actually present, so that
    installs and instructions match the machine instead of assuming Ubuntu.
    """
    global _PLATFORM_CACHE
    if _PLATFORM_CACHE and not refresh:
        return _PLATFORM_CACHE

    system_raw = platform.system()
    if system_raw == "Darwin":
        system = "macos"
    elif system_raw == "Windows":
        system = "windows"
    elif system_raw == "Linux":
        system = "linux"
    else:
        system = system_raw.lower() or "unknown"

    os_release = _read_os_release() if system == "linux" else {}
    family = _distro_family(os_release) if system == "linux" else system

    if system == "windows":
        candidates = ["winget", "scoop", "choco", "go", "pip"]
    elif system == "macos":
        candidates = ["brew", "port", "go", "pip", "cargo"]
    else:
        candidates = ["apt", "dnf", "yum", "pacman", "zypper", "apk", "snap",
                      "brew", "go", "pip", "cargo"]

    manager_binaries = {
        "apt": "apt-get", "dnf": "dnf", "yum": "yum", "pacman": "pacman",
        "zypper": "zypper", "apk": "apk", "snap": "snap", "brew": "brew",
        "port": "port", "winget": "winget", "scoop": "scoop", "choco": "choco",
        "go": "go", "cargo": "cargo", "pip": "pip3",
    }
    managers: Dict[str, str] = {}
    for manager in candidates:
        binary = manager_binaries[manager]
        found = _which(binary)
        if not found and manager == "pip":
            found = _which("pip")
        if found:
            managers[manager] = found

    is_root = bool(system != "windows" and hasattr(os, "geteuid") and os.geteuid() == 0)
    sudo_path = _which("sudo") if system != "windows" else None
    sudo_mode = "root" if is_root else "unavailable"
    if not is_root and sudo_path:
        try:
            probe = subprocess.run([sudo_path, "-n", "true"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
            sudo_mode = "passwordless" if probe.returncode == 0 else "password-required"
        except Exception:
            sudo_mode = "password-required"

    info = {
        "system": system,
        "system_label": {"macos": "macOS", "windows": "Windows",
                         "linux": "Linux"}.get(system, system_raw or "unknown"),
        "release": platform.release(),
        "arch": platform.machine(),
        "distro": os_release.get("PRETTY_NAME") or os_release.get("NAME") or "",
        "distro_id": (os_release.get("ID") or "").lower(),
        "distro_family": family,
        "package_managers": managers,
        "is_root": is_root,
        "sudo": sudo_mode,
        "can_elevate": is_root or sudo_mode == "passwordless",
        "in_docker": Path("/.dockerenv").exists(),
        "in_wsl": "microsoft" in platform.release().lower(),
        "python": platform.python_version(),
    }
    _PLATFORM_CACHE = info
    return info


def _sudo_prefix(manager: str) -> Optional[List[str]]:
    """
    Command prefix needed to run a package manager. None means "cannot run this
    without prompting for a password" - we never hang the app on a sudo prompt.
    """
    if manager not in _ROOT_MANAGERS:
        return []
    info = detect_platform()
    if info["system"] == "windows":
        return []  # choco needs an elevated shell; we surface that as an instruction
    if info["is_root"]:
        return []
    if info["sudo"] == "passwordless":
        return ["sudo", "-n"]
    return None


def _install_command(manager: str, package: str) -> List[str]:
    """The command that installs `package` with `manager`, without any sudo prefix."""
    commands = {
        "apt": ["apt-get", "install", "-y", package],
        "dnf": ["dnf", "install", "-y", package],
        "yum": ["yum", "install", "-y", package],
        "pacman": ["pacman", "-S", "--noconfirm", package],
        "zypper": ["zypper", "--non-interactive", "install", package],
        "apk": ["apk", "add", package],
        "snap": ["snap", "install", package],
        "brew": ["brew", "install", package],
        "port": ["port", "install", package],
        "winget": ["winget", "install", "--id", package, "-e",
                   "--accept-package-agreements", "--accept-source-agreements"],
        "scoop": ["scoop", "install", package],
        "choco": ["choco", "install", package, "-y"],
        "go": ["go", "install", "-v", package],
        "cargo": ["cargo", "install", package],
        "pip": [sys.executable, "-m", "pip", "install", "--user", package],
    }
    return commands.get(manager, [])


def _package_available(manager: str, package: str) -> bool:
    """
    Ask the package manager whether it actually has this package, so we never
    print an install line that cannot work. Unknown managers are optimistic.
    """
    key = (manager, package)
    if key in _PKG_AVAILABILITY_CACHE:
        return _PKG_AVAILABILITY_CACHE[key]

    probes = {
        "apt": ["apt-cache", "policy", package],
        "dnf": ["dnf", "-q", "info", package],
        "yum": ["yum", "-q", "info", package],
        "pacman": ["pacman", "-Si", package],
        "zypper": ["zypper", "-q", "info", package],
        "apk": ["apk", "policy", package],
        "snap": ["snap", "info", package],
        "brew": ["brew", "info", "--formula", package],
        "port": ["port", "info", package],
    }
    probe = probes.get(manager)
    if not probe:
        # go/cargo/pip/winget/scoop/choco: resolved at install time.
        _PKG_AVAILABILITY_CACHE[key] = True
        return True

    try:
        result = subprocess.run(probe, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=30)
        output = ((result.stdout or "") + (result.stderr or "")).lower()
        if manager == "apt":
            available = "candidate:" in output and "candidate: (none)" not in output
        elif manager == "apk":
            available = bool(output.strip()) and "policy" in output
        else:
            available = result.returncode == 0 and "not found" not in output
    except Exception:
        available = False

    _PKG_AVAILABILITY_CACHE[key] = available
    return available


def _method_label(manager: str) -> str:
    labels = {
        "apt": "APT", "dnf": "DNF", "yum": "YUM", "pacman": "pacman", "zypper": "zypper",
        "apk": "apk", "snap": "Snap", "brew": "Homebrew", "port": "MacPorts",
        "winget": "winget", "scoop": "Scoop", "choco": "Chocolatey",
        "go": "go install", "cargo": "cargo install", "pip": "pip",
    }
    return labels.get(manager, manager)


def _manager_priority(system: str) -> List[str]:
    if system == "macos":
        return ["brew", "port", "go", "cargo", "pip"]
    if system == "windows":
        return ["scoop", "winget", "choco", "go", "cargo", "pip"]
    return ["apt", "dnf", "yum", "pacman", "zypper", "apk", "snap", "brew",
            "go", "cargo", "pip"]


def build_install_plan(tool: str, include_unavailable: bool = False) -> List[Dict[str, Any]]:
    """
    Ordered install methods for this machine. Each entry says what would run,
    whether the manager is present, whether the package exists there, and
    whether it can run unattended.
    """
    info = detect_platform()
    packages = TOOL_PACKAGES.get(tool, {})
    managers = info["package_managers"]
    plan: List[Dict[str, Any]] = []

    for manager in _manager_priority(info["system"]):
        package = packages.get(manager)
        if not package:
            continue
        present = manager in managers
        if not present and not include_unavailable:
            continue
        available = _package_available(manager, package) if present else False
        prefix = _sudo_prefix(manager) if present else []
        needs_root = manager in _ROOT_MANAGERS and not info["is_root"] and info["system"] != "windows"
        command = _install_command(manager, package)
        display = " ".join((["sudo"] if needs_root else []) + command)
        plan.append({
            "manager": manager,
            "label": _method_label(manager),
            "package": package,
            "command": command,
            "display_command": display,
            "manager_present": present,
            "package_available": available,
            "needs_root": needs_root,
            "can_run_unattended": bool(present and available and prefix is not None),
            "blocked_reason": ("sudo would prompt for a password" if present and prefix is None
                               else ("package not offered by this manager" if present and not available
                                     else ("" if present else "manager not installed"))),
            "sudo_prefix": prefix or [],
        })
    return plan


def get_tool_installation_instructions(tool: str) -> str:
    """
    Installation instructions for THIS machine: detected OS first, with the
    commands that actually apply, then the fallbacks.
    """
    info = detect_platform()
    lines: List[str] = []
    title = f"{tool.upper()} - installation"
    lines.append(title)
    lines.append("=" * len(title))
    detected = info["system_label"]
    if info["distro"]:
        detected += f" ({info['distro']})"
    lines.append(f"Detected system: {detected} on {info['arch']}")
    if tool in TOOL_NOTES:
        lines.append(f"Note: {TOOL_NOTES[tool]}")
    lines.append("")

    if tool == "crtsh" or not TOOL_PACKAGES.get(tool):
        lines.append("Nothing to install for this tool.")
        docs = TOOL_DOCS.get(tool)
        if docs:
            lines.append(f"Docs: {docs}")
        return "\n".join(lines)

    plan = build_install_plan(tool, include_unavailable=True)
    usable = [step for step in plan if step["manager_present"] and step["package_available"]]
    if usable:
        lines.append("Run one of these:")
        for step in usable:
            lines.append(f"  {step['display_command']}          # {step['label']}")
            if step["blocked_reason"]:
                lines.append(f"      ({step['blocked_reason']})")
    else:
        lines.append("No package manager on this machine offers it. Options:")

    others = [step for step in plan if step not in usable]
    if others:
        lines.append("")
        lines.append("Other options:")
        for step in others:
            suffix = f"  # {step['label']}"
            if not step["manager_present"]:
                suffix += f" - install {step['label']} first"
            elif not step["package_available"]:
                suffix += f" - {step['label']} does not offer this package here"
            lines.append(f"  {step['display_command']}{suffix}")

    if "go" in TOOL_PACKAGES.get(tool, {}) and "go" not in info["package_managers"]:
        lines.append("")
        lines.append("Go is not installed. Get it from https://go.dev/dl/ and make sure")
        lines.append("its bin directory is on PATH (~/go/bin, or %USERPROFILE%\\go\\bin on Windows).")

    docs = TOOL_DOCS.get(tool)
    if docs:
        lines.append("")
        lines.append(f"Docs and release binaries: {docs}")
    if info["system"] == "windows" and not TOOL_PACKAGES.get(tool, {}).get("go"):
        lines.append("No supported Windows package - download a release binary and put it on PATH.")
    return "\n".join(lines)


def _run_install_step(tool: str, step: Dict[str, Any]) -> bool:
    """Run one install method. Never prompts, never blocks forever."""
    global _APT_UPDATED
    command = list(step["sudo_prefix"]) + list(step["command"])
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    if step["manager"] == "apt" and not _APT_UPDATED:
        try:
            subprocess.run(list(step["sudo_prefix"]) + ["apt-get", "update"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=300, env=env, check=False)
        except Exception as exc:
            log(f"apt-get update failed before installing {tool}: {exc}")
        _APT_UPDATED = True

    log(f"Installing {tool} via {step['label']}: {' '.join(command)}")
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=900, env=env, check=False)
    except subprocess.TimeoutExpired:
        log(f"{step['label']} install of {tool} timed out.")
        return False
    except Exception as exc:
        log(f"{step['label']} install of {tool} failed: {exc}")
        return False

    if result.returncode != 0:
        tail = (result.stdout or "").strip().splitlines()[-3:]
        log(f"{step['label']} install of {tool} exited {result.returncode}. {' | '.join(tail)}")
        return False
    return True


def ensure_tool_installed(tool: str) -> bool:
    """
    Install a tool using a method that fits this OS. Methods that would prompt
    for a password or that the local package manager cannot satisfy are skipped
    rather than attempted and failed.
    Returns True if the tool is usable afterwards.
    """
    if tool == "crtsh":
        TOOLS[tool] = "crtsh"  # virtual, API-based
        return True

    resolved = resolve_tool_path_cached(tool)
    if resolved:
        TOOLS[tool] = resolved
        log(f"{tool} already installed.")
        return True

    skip_auto = str(os.environ.get("SUBSCRAPER_SKIP_AUTO_INSTALL") or "").strip().lower()
    if skip_auto in ("1", "true", "yes", "on"):
        log(f"{tool} not found. Auto-install disabled (SUBSCRAPER_SKIP_AUTO_INSTALL).")
        return False


    info = detect_platform()
    log(f"{tool} not found. Detected {info['system_label']}"
        + (f" / {info['distro']}" if info["distro"] else "")
        + f"; trying automatic install.")

    plan = build_install_plan(tool)
    runnable = [step for step in plan if step["can_run_unattended"]]
    if not runnable:
        skipped = [f"{step['label']} ({step['blocked_reason']})" for step in plan if step["blocked_reason"]]
        if skipped:
            log(f"No unattended install path for {tool}: {', '.join(skipped)}")

    for step in runnable:
        if not _run_install_step(tool, step):
            continue
        invalidate_tool_path_cache(tool)
        resolved = _resolve_tool_path(tool)
        if resolved:
            TOOLS[tool] = resolved
            log(f"{tool} installed via {step['label']}.")
            return True
        log(f"{step['label']} reported success for {tool} but the binary is still not on PATH.")

    log(f"Could not auto-install {tool}. Instructions for this machine:")
    print("\n" + get_tool_installation_instructions(tool))
    return False


def tool_status_snapshot(include_instructions: bool = True) -> Dict[str, Any]:
    """Per-tool availability plus the install plan that fits this machine."""
    info = detect_platform()
    tools: List[Dict[str, Any]] = []
    for name in TOOLS.keys():
        path = "crtsh" if name == "crtsh" else (resolve_tool_path_cached(name) or "")
        entry: Dict[str, Any] = {
            "tool": name,
            "installed": bool(path),
            "path": path,
            "virtual": name == "crtsh",
            "note": TOOL_NOTES.get(name, ""),
            "docs": TOOL_DOCS.get(name, ""),
        }
        if not path:
            plan = build_install_plan(name, include_unavailable=True)
            entry["install_plan"] = [
                {key: step[key] for key in
                 ("manager", "label", "package", "display_command", "manager_present",
                  "package_available", "needs_root", "can_run_unattended", "blocked_reason")}
                for step in plan
            ]
            entry["auto_installable"] = any(step["can_run_unattended"] for step in plan)
            if include_instructions:
                entry["instructions"] = get_tool_installation_instructions(name)
        else:
            entry["install_plan"] = []
            entry["auto_installable"] = True
        tools.append(entry)

    return {
        "platform": {key: value for key, value in info.items() if key != "package_managers"},
        "package_managers": sorted(info["package_managers"].keys()),
        "tools": tools,
        "installed_count": sum(1 for entry in tools if entry["installed"]),
        "total_count": len(tools),
    }


def ensure_required_tools() -> None:
    info = detect_platform()
    log(f"Verifying required tooling on {info['system_label']}"
        + (f" ({info['distro']})" if info["distro"] else "")
        + f" - package managers: {', '.join(sorted(info['package_managers'])) or 'none detected'}")
    if info["system"] != "windows" and not info["can_elevate"]:
        log("No passwordless sudo: system-package installs are skipped and reported instead.")
    for name in TOOLS.keys():
        ensure_tool_installed(name)
