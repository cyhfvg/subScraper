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
    print("\n1. Default Wordlist for Subdomain Brute-Force (dnsx DNS + ffuf)")
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
    
    print("\n" + "-"*70)
    print("INTRANET SETTINGS")
    print("-"*70)
    print("\n4. DNS resolvers (intranet)")
    print("   Comma-separated IPs used by DNSx. Empty = OS resolver.")
    try:
        resolvers = input("   Resolvers (or Enter to skip): ").strip()
        if resolvers:
            config["dns_resolvers"] = _normalize_resolver_list(resolvers)
            print(f"   Set {len(config['dns_resolvers'])} resolver(s)")
        else:
            print("   Skipped")
    except (EOFError, KeyboardInterrupt):
        print("   Skipped")

    print("\n5. Port scan spec")
    print("   nmap -p list, or top-N such as top-1000.")
    try:
        ports = input(f"   Ports (Enter for default): ").strip()
        if ports:
            config["port_scan_ports"] = ports
            print(f"   Set port_scan_ports={ports}")
        else:
            print("   Using built-in intranet port set")
    except (EOFError, KeyboardInterrupt):
        print("   Skipped")

    print("\n" + "-"*70)
    print("SAVING CONFIGURATION")
    print("-"*70)

    config["setup_completed"] = True
    save_config(config)
    print("Configuration saved.")

    print("\n" + "="*70)
    print("SETUP COMPLETE")
    print("="*70)
    print("\nConfiguration Summary:")
    print(f"   Wordlist: {config.get('default_wordlist') or 'Not configured'}")
    print(f"   Concurrent Jobs: {config.get('max_running_jobs', 1)}")
    print(f"   Skip Nikto: {'Yes' if config.get('skip_nikto_by_default') else 'No'}")
    print(f"   DNS resolvers: {', '.join(config.get('dns_resolvers') or []) or '(system)'}")
    print("\nNext steps:")
    print("   1. Install local tools: nmap, dnsx, ffuf, httpx, nuclei, nikto, gowitness")
    print("   2. python3 main.py")
    print("   3. Or: python3 main.py 10.0.0.0/24 --wordlist /path/to/hosts.txt")
    print("="*70 + "\n")


