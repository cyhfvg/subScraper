"""Fragment 12_run_setup_wizard.py. Loaded into the main module namespace."""
def run_setup_wizard() -> None:
    """
    Interactive first-run setup wizard to configure all settings and API keys.
    This prevents the program from freezing during execution by collecting all
    required information upfront.
    """
    print("\n" + "="*70)
    print("    🚀 WELCOME TO SUBSCRAPER - FIRST RUN SETUP WIZARD")
    print("="*70)
    print("\nThis wizard will help you configure subScraper for optimal performance.")
    print("You can skip any setting by pressing Enter (defaults will be used).")
    print("You can always change these settings later in the web UI.\n")
    
    config = get_config()
    
    # Admin Account Setup
    print("\n" + "-"*70)
    print("👤 ADMIN ACCOUNT SETUP")
    print("-"*70)
    print("\nTo secure the web interface, you need to create an admin account.")
    print("This account will have full access to all features and can create")
    print("additional user accounts.\n")
    
    admin_created = False
    if has_admin_user():
        print("✓ Admin account already exists.")
        admin_created = True
    else:
        while not admin_created:
            try:
                username = input("Admin username (min 3 chars): ").strip()
                if not username:
                    print("⚠ Username is required. Please try again.")
                    continue
                
                password = input("Admin password (min 6 chars): ").strip()
                if not password:
                    print("⚠ Password is required. Please try again.")
                    continue
                
                password_confirm = input("Confirm password: ").strip()
                if password != password_confirm:
                    print("⚠ Passwords don't match. Please try again.\n")
                    continue
                
                success, message = create_user(username, password, is_admin=True)
                if success:
                    print(f"✓ {message}")
                    admin_created = True
                else:
                    print(f"⚠ {message}. Please try again.\n")
            except (EOFError, KeyboardInterrupt):
                print("\n\n⚠ Admin account creation is required to continue.")
                print("Press Ctrl+C again to exit or Enter to continue...")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    print("\nSetup cancelled. Exiting...")
                    sys.exit(1)
    
    # Basic Settings
    print("\n" + "-"*70)
    print("📋 BASIC SETTINGS")
    print("-"*70)
    
    # Wordlist configuration
    print("\n1. Default Wordlist for Subdomain Brute-Force (ffuf)")
    print("   Recommended: Download a wordlist like SecLists subdomains-top1million-5000.txt")
    current_wordlist = config.get("default_wordlist", "")
    if current_wordlist:
        print(f"   Current: {current_wordlist}")
    try:
        wordlist = input("   Enter wordlist path (or press Enter to skip): ").strip()
        if wordlist and Path(wordlist).exists():
            config["default_wordlist"] = wordlist
            print(f"   ✓ Wordlist set to: {wordlist}")
        elif wordlist:
            print(f"   ⚠ Warning: File not found: {wordlist}. You can set this later.")
            config["default_wordlist"] = wordlist
        else:
            print("   ⏭ Skipped (you can add this later in Settings)")
    except (EOFError, KeyboardInterrupt):
        print("\n   ⏭ Skipped")
    
    # Concurrency settings
    print("\n2. Concurrent Jobs")
    print(f"   Current: {config.get('max_running_jobs', 1)}")
    print("   How many scans should run simultaneously? (1-10 recommended)")
    try:
        jobs = input("   Enter number (or press Enter for default): ").strip()
        if jobs:
            config["max_running_jobs"] = max(1, min(20, int(jobs)))
            print(f"   ✓ Set to: {config['max_running_jobs']} concurrent jobs")
        else:
            print("   ⏭ Using default: 1")
    except (ValueError, EOFError, KeyboardInterrupt):
        print("   ⏭ Using default: 1")
    
    # Nikto settings
    print("\n3. Skip Nikto by Default?")
    print("   Nikto scans can be slow. Skip them unless explicitly needed?")
    try:
        skip = input("   Skip Nikto? (y/N): ").strip().lower()
        config["skip_nikto_by_default"] = (skip == 'y')
        print(f"   ✓ {'Will skip' if config['skip_nikto_by_default'] else 'Will run'} Nikto by default")
    except (EOFError, KeyboardInterrupt):
        print("   ⏭ Using default: Run Nikto")
    
    # API Keys Configuration
    print("\n" + "-"*70)
    print("🔑 API KEYS SETUP")
    print("-"*70)
    print("\nMany tools work better with API keys for better results and rate limits.")
    print("You can skip these and add them later, but adding them now is recommended.\n")
    
    # Amass API keys
    print("4. Amass Configuration")
    print("   Amass supports multiple data sources with API keys:")
    print("   - Shodan, VirusTotal, SecurityTrails, Censys, PassiveTotal, etc.")
    
    amass_config_dir = Path.home() / ".config" / "amass"
    amass_config_file = amass_config_dir / "config.ini"
    
    if amass_config_file.exists():
        print(f"   ✓ Amass config already exists at: {amass_config_file}")
        try:
            update = input("   Update Amass API keys? (y/N): ").strip().lower()
            if update != 'y':
                print("   ⏭ Keeping existing Amass config")
            else:
                setup_amass_config(amass_config_dir, amass_config_file)
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Keeping existing Amass config")
    else:
        try:
            setup = input("   Configure Amass API keys now? (Y/n): ").strip().lower()
            if setup == 'n':
                print("   ⏭ Skipped Amass setup")
            else:
                setup_amass_config(amass_config_dir, amass_config_file)
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Skipped Amass setup")
    
    # Subfinder API keys
    print("\n5. Subfinder Configuration")
    print("   Subfinder also supports various API sources.")
    subfinder_config_dir = Path.home() / ".config" / "subfinder"
    subfinder_config_file = subfinder_config_dir / "provider-config.yaml"
    
    if subfinder_config_file.exists():
        print(f"   ✓ Subfinder config already exists at: {subfinder_config_file}")
        try:
            update = input("   Update Subfinder API keys? (y/N): ").strip().lower()
            if update == 'y':
                setup_subfinder_config(subfinder_config_dir, subfinder_config_file)
            else:
                print("   ⏭ Keeping existing Subfinder config")
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Keeping existing Subfinder config")
    else:
        try:
            setup = input("   Configure Subfinder API keys now? (Y/n): ").strip().lower()
            if setup == 'n':
                print("   ⏭ Skipped Subfinder setup")
            else:
                setup_subfinder_config(subfinder_config_dir, subfinder_config_file)
        except (EOFError, KeyboardInterrupt):
            print("   ⏭ Skipped Subfinder setup")
    
    # Save configuration
    print("\n" + "-"*70)
    print("💾 SAVING CONFIGURATION")
    print("-"*70)
    
    config["setup_completed"] = True
    save_config(config)
    print("✓ Configuration saved successfully!")
    
    # Display summary and next steps
    print("\n" + "="*70)
    print("✅ SETUP COMPLETE!")
    print("="*70)
    print("\n📊 Configuration Summary:")
    print(f"   • Wordlist: {config.get('default_wordlist') or 'Not configured (optional)'}")
    print(f"   • Concurrent Jobs: {config.get('max_running_jobs', 1)}")
    print(f"   • Skip Nikto: {'Yes' if config.get('skip_nikto_by_default') else 'No'}")
    print(f"   • Amass Config: {'✓ Configured' if amass_config_file.exists() else '⏭ Skipped'}")
    print(f"   • Subfinder Config: {'✓ Configured' if subfinder_config_file.exists() else '⏭ Skipped'}")
    
    print("\n" + "-"*70)
    print("🚀 NEXT STEPS TO GET THE FULL PROGRAM WORKING")
    print("-"*70)
    print("\n1. VERIFY TOOLS INSTALLATION")
    print("   All required tools should be installed automatically.")
    print("   If any tool is missing, install it manually:")
    print("   - amass, subfinder, assetfinder, findomain, sublist3r")
    print("   - ffuf, httpx, nuclei, nikto, gowitness")
    print("   - waybackurls, gau, dnsx")
    
    print("\n2. INSTALL PYTHON DEPENDENCIES (if not already done)")
    print("   $ pip3 install -r requirements.txt")
    
    print("\n3. START THE WEB SERVER")
    print("   $ python3 main.py")
    print("   Then open: http://0.0.0.0:8342 (or http://<your-ip>:8342)")
    
    print("\n4. OR RUN A DIRECT SCAN")
    print("   $ python3 main.py example.com --wordlist /path/to/wordlist.txt")
    
    print("\n5. CONFIGURE MORE SETTINGS (optional)")
    print("   • Open the web UI → Settings tab")
    print("   • Configure tool-specific flags and templates")
    print("   • Set up monitoring feeds")
    print("   • Enable dynamic queue management")
    print("   • Configure auto-backup")
    
    print("\n6. DOWNLOAD A WORDLIST (if you haven't)")
    print("   Popular options:")
    print("   • SecLists: https://github.com/danielmiessler/SecLists")
    print("   • DNS wordlists: subdomains-top1million-5000.txt")
    
    print("\n" + "="*70)
    print("📚 For more information:")
    print("   • README.md - Full documentation")
    print("   • QUICKSTART.md - Quick start guide")
    print("   • Web UI Settings - Configure everything through the interface")
    print("="*70 + "\n")


def setup_amass_config(config_dir: Path, config_file: Path) -> None:
    """Setup Amass configuration with API keys."""
    config_dir.mkdir(parents=True, exist_ok=True)
    
    providers = {
        "shodan": "Shodan API (https://account.shodan.io/)",
        "virustotal": "VirusTotal API (https://www.virustotal.com/gui/my-apikey)",
        "securitytrails": "SecurityTrails API (https://securitytrails.com/app/account/credentials)",
        "censys": "Censys API (https://search.censys.io/account/api)",
        "passivetotal": "PassiveTotal/RiskIQ API (https://community.riskiq.com/settings)",
        "binaryedge": "BinaryEdge API (https://app.binaryedge.io/account/api)",
        "bevigil": "BeVigil API (https://bevigil.com/osint-api)",
    }
    
    api_keys = {}
    print("\n   Press Enter to skip any provider.")
    for name, description in providers.items():
        print(f"\n   {description}")
        try:
            key = input(f"   Enter API key for {name} (or press Enter to skip): ").strip()
            if key:
                api_keys[name] = key
                print(f"   ✓ {name} API key saved")
        except (EOFError, KeyboardInterrupt):
            break
    
    # Write config.ini
    lines = [
        "# Generated by subScraper setup wizard",
        "# You can edit this file later to add more API keys",
        "[resolvers]",
        "resolver = 1.1.1.1",
        "resolver = 8.8.8.8",
        "",
        "[scope]",
        "# Add scope settings here if needed",
        "",
        "[datasources]",
    ]
    
    for name, key in api_keys.items():
        lines.append(f"[datasources.{name}]")
        lines.append(f"[datasources.{name}.Credentials]")
        lines.append(f"apikey = {key}")
        lines.append("")
    
    # Add commented templates for providers not configured
    for name in providers.keys():
        if name not in api_keys:
            lines.append(f"# [{name}]")
            lines.append(f"# [datasources.{name}.Credentials]")
            lines.append("# apikey = YOUR_KEY_HERE")
            lines.append("")
    
    atomic_write_text(config_file, "\n".join(lines))
    print(f"\n   ✓ Amass config created at: {config_file}")
    if api_keys:
        print(f"   ✓ Configured {len(api_keys)} API key(s)")
    else:
        print("   ⏭ No API keys configured (you can add them later)")


def setup_subfinder_config(config_dir: Path, config_file: Path) -> None:
    """Setup Subfinder configuration with API keys."""
    config_dir.mkdir(parents=True, exist_ok=True)
    
    providers = {
        "shodan": "Shodan API",
        "censys": "Censys API",
        "virustotal": "VirusTotal API",
        "binaryedge": "BinaryEdge API",
        "securitytrails": "SecurityTrails API",
        "passivetotal": "PassiveTotal API",
        "github": "GitHub Personal Access Token",
    }
    
    api_keys = {}
    print("\n   Press Enter to skip any provider.")
    for name, description in providers.items():
        try:
            key = input(f"   Enter {description} (or press Enter to skip): ").strip()
            if key:
                api_keys[name] = key
                print(f"   ✓ {name} saved")
        except (EOFError, KeyboardInterrupt):
            break
    
    # Create YAML config
    lines = ["# Generated by subScraper setup wizard"]
    for name, key in api_keys.items():
        lines.append(f"{name}: [{key}]")
    
    if not api_keys:
        lines.append("# Add your API keys here")
        lines.append("# Format: provider: [api_key]")
        lines.append("# Example:")
        lines.append("# shodan: [your_api_key_here]")
    
    atomic_write_text(config_file, "\n".join(lines))
    print(f"\n   ✓ Subfinder config created at: {config_file}")
    if api_keys:
        print(f"   ✓ Configured {len(api_keys)} API key(s)")
    else:
        print("   ⏭ No API keys configured (you can add them later)")


# ================== API KEY MANAGEMENT ==================

def read_amass_api_keys() -> Dict[str, str]:
    """Read API keys from Amass config file."""
    config_file = Path.home() / ".config" / "amass" / "config.ini"
    api_keys = {}
    
    if not config_file.exists():
        return api_keys
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse simple INI format for datasources
        # Look for patterns like [datasources.provider] followed by apikey = value
        pattern = r'\[datasources\.(\w+)\.Credentials\]\s*\napikey\s*=\s*(.+?)(?:\n|$)'
        matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
        
        for provider, key in matches:
            api_keys[provider.lower()] = key.strip()
    
    except Exception as exc:
        log(f"Error reading Amass config: {exc}")
    
    return api_keys


def write_amass_api_keys(api_keys: Dict[str, str]) -> Tuple[bool, str]:
    """Write API keys to Amass config file."""
    config_dir = Path.home() / ".config" / "amass"
    config_file = config_dir / "config.ini"
    
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Build config content
        lines = [
            "# Generated by subScraper",
            "# You can edit this file to add or update API keys",
            "[resolvers]",
            "resolver = 1.1.1.1",
            "resolver = 8.8.8.8",
            "",
            "[scope]",
            "# Add scope settings here if needed",
            "",
            "[datasources]",
        ]
        
        # Add API keys for providers that have them
        for provider in AMASS_PROVIDERS:
            if provider in api_keys and api_keys[provider].strip():
                lines.append(f"[datasources.{provider}]")
                lines.append(f"[datasources.{provider}.Credentials]")
                lines.append(f"apikey = {api_keys[provider].strip()}")
                lines.append("")
        
        # Add commented templates for providers without keys
        for provider in AMASS_PROVIDERS:
            if provider not in api_keys or not api_keys[provider].strip():
                lines.append(f"# [datasources.{provider}]")
                lines.append(f"# [datasources.{provider}.Credentials]")
                lines.append("# apikey = YOUR_KEY_HERE")
                lines.append("")
        
        atomic_write_text(config_file, "\n".join(lines))
        return True, f"Amass API keys saved to {config_file}"
    
    except Exception as exc:
        return False, f"Error saving Amass config: {exc}"


def read_subfinder_api_keys() -> Dict[str, str]:
    """Read API keys from Subfinder config file."""
    config_file = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
    api_keys = {}
    
    if not config_file.exists():
        return api_keys
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse simple YAML format: provider: [key]
        pattern = r'^(\w+):\s*\[([^\]]+)\]'
        matches = re.findall(pattern, content, re.MULTILINE)
        
        for provider, key in matches:
            api_keys[provider.lower()] = key.strip()
    
    except Exception as exc:
        log(f"Error reading Subfinder config: {exc}")
    
    return api_keys


def write_subfinder_api_keys(api_keys: Dict[str, str]) -> Tuple[bool, str]:
    """Write API keys to Subfinder config file."""
    config_dir = Path.home() / ".config" / "subfinder"
    config_file = config_dir / "provider-config.yaml"
    
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Build YAML content
        lines = ["# Generated by subScraper"]
        
        # Add API keys for providers that have them
        for provider in SUBFINDER_PROVIDERS:
            if provider in api_keys and api_keys[provider].strip():
                lines.append(f"{provider}: [{api_keys[provider].strip()}]")
        
        # Add commented examples for providers without keys
        if not any(provider in api_keys and api_keys[provider].strip() for provider in SUBFINDER_PROVIDERS):
            lines.append("# Add your API keys here")
            lines.append("# Format: provider: [api_key]")
            lines.append("# Example:")
            lines.append("# shodan: [your_api_key_here]")
        
        atomic_write_text(config_file, "\n".join(lines))
        return True, f"Subfinder API keys saved to {config_file}"
    
    except Exception as exc:
        return False, f"Error saving Subfinder config: {exc}"


def get_all_api_keys() -> Dict[str, Any]:
    """Get all API keys from both Amass and Subfinder configs."""
    return {
        "amass": read_amass_api_keys(),
        "subfinder": read_subfinder_api_keys(),
    }
