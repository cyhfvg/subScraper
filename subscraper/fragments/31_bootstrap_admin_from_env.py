"""Fragment 31_bootstrap_admin_from_env.py. Loaded into the main module namespace."""
def bootstrap_admin_from_env() -> bool:
    """
    从环境变量创建首个管理员, 供 Docker / 非交互启动使用.

    Args:
        无. 读取 SUBSCRAPER_ADMIN_USER 与 SUBSCRAPER_ADMIN_PASSWORD.

    Returns:
        bool: 已有管理员或创建成功时为 True, 否则 False.

    Raises:
        无. 失败只写日志.

    调用示例:
        bootstrap_admin_from_env()
    """
    if has_admin_user():
        return True
    username = str(os.environ.get("SUBSCRAPER_ADMIN_USER") or "").strip()
    password = str(os.environ.get("SUBSCRAPER_ADMIN_PASSWORD") or "")
    if not username or not password:
        return False
    success, message = create_user(username, password, is_admin=True)
    if success:
        log(f"Admin user '{username}' created from environment variables.")
        return True
    log(f"ERROR: Failed to create admin from environment: {message}")
    return False


def prompt_admin_creation() -> bool:
    """
    Prompt for admin account creation if none exists (interactive mode only).
    Returns True if admin exists or was created, False if cancelled.
    """
    if has_admin_user():
        return True

    if bootstrap_admin_from_env():
        return True

    if not sys.stdin.isatty():
        log("ERROR: No admin account exists and running in non-interactive mode.")
        log("Set SUBSCRAPER_ADMIN_USER and SUBSCRAPER_ADMIN_PASSWORD, or run interactively.")
        return False

    print("\n" + "="*70)
    print("⚠️  ADMIN ACCOUNT REQUIRED")
    print("="*70)
    print("\nNo admin account exists. You need to create one to access the web UI.")
    print("This account will have full access and can create additional users.\n")

    while True:
        try:
            username = input("Admin username (min 3 chars): ").strip()
            if not username:
                print("⚠ Username is required.")
                continue

            password = input("Admin password (min 6 chars): ").strip()
            if not password:
                print("⚠ Password is required.")
                continue

            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("⚠ Passwords don't match. Please try again.\n")
                continue

            success, message = create_user(username, password, is_admin=True)
            if success:
                print(f"✓ {message}\n")
                return True
            else:
                print(f"⚠ {message}. Please try again.\n")
        except (EOFError, KeyboardInterrupt):
            print("\n\nAdmin account creation cancelled.")
            print("An admin account is required to run the web server.")
            return False



def generate_self_signed_cert(cert_file: Path, key_file: Path) -> bool:
    """
    Generate a self-signed SSL certificate for HTTPS.
    Returns True if successful, False otherwise.
    """
    try:
        log("Generating self-signed SSL certificate...")
        
        # Use OpenSSL to generate a self-signed certificate
        # Valid for 365 days with 2048-bit RSA key
        cmd = [
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "365",
            "-nodes", "-x509",
            "-subj", "/C=US/ST=State/L=City/O=Organization/CN=localhost",
            "-keyout", str(key_file),
            "-out", str(cert_file)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            log(f"✓ Self-signed certificate generated:")
            log(f"  Certificate: {cert_file}")
            log(f"  Private key: {key_file}")
            log("  Note: Browsers will show a security warning for self-signed certificates.")
            log("  For production use, obtain a certificate from a trusted CA (e.g., Let's Encrypt).")
            return True
        else:
            log(f"ERROR: Failed to generate certificate: {result.stderr}")
            return False
    except FileNotFoundError:
        log("ERROR: OpenSSL not found. Please install OpenSSL to use HTTPS with auto-generated certificates.")
        log("  Ubuntu/Debian: sudo apt-get install openssl")
        log("  macOS: brew install openssl")
        log("  Or provide your own certificate with --cert and --key arguments.")
        return False
    except Exception as e:
        log(f"ERROR: Failed to generate certificate: {e}")
        return False


def run_server(host: str, port: int, interval: int, use_https: bool = False, cert_file: Optional[str] = None, key_file: Optional[str] = None) -> None:
    global HTML_REFRESH_SECONDS, COMPLETED_JOBS
    config = get_config()
    refresh = interval or config.get("default_interval", DEFAULT_INTERVAL)
    HTML_REFRESH_SECONDS = max(5, refresh)
    ensure_dirs()
    
    # Load completed jobs from disk
    loaded_jobs = load_completed_jobs()
    with JOB_LOCK:
        COMPLETED_JOBS.clear()
        COMPLETED_JOBS.update(loaded_jobs)
    log(f"Loaded {len(loaded_jobs)} completed job(s) from disk.")
    
    start_monitor_worker()
    start_system_resource_worker()  # Start system resource monitoring
    start_session_cleanup_worker()  # Start session cleanup

    # Re-dispatch jobs that were active before the last shutdown, then start the
    # periodic persister so future restarts can resume too.
    try:
        restore_active_jobs()
    except Exception as exc:
        log(f"Job restore failed: {exc}")
    start_active_jobs_persister()

    generate_html_dashboard()
    server = ThreadingHTTPServer((host, port), CommandCenterHandler)
    
    # Configure HTTPS if requested
    if use_https:
        # Determine certificate and key paths
        if cert_file and key_file:
            cert_path = Path(cert_file)
            key_path = Path(key_file)
            
            if not cert_path.exists():
                log(f"ERROR: Certificate file not found: {cert_file}")
                return
            if not key_path.exists():
                log(f"ERROR: Key file not found: {key_file}")
                return
        else:
            # Generate self-signed certificate
            cert_path = DATA_DIR / "server.crt"
            key_path = DATA_DIR / "server.key"
            
            # Only generate if they don't exist
            if not cert_path.exists() or not key_path.exists():
                if not generate_self_signed_cert(cert_path, key_path):
                    log("ERROR: Failed to set up HTTPS. Starting HTTP server instead...")
                    use_https = False
        
        if use_https:
            # Wrap the socket with SSL
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_path), str(key_path))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            log(f"🔒 Recon Command Center available at https://{host}:{port}")
            log(f"   Using certificate: {cert_path}")
    
    if not use_https:
        log(f"Recon Command Center available at http://{host}:{port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Web server interrupted by user.")
    finally:
        server.server_close()

# ================== CLI ==================

def main():
    parser = argparse.ArgumentParser(description="Recon pipeline + web command center")
    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain / TLD (if omitted, launch the web UI instead)."
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Wordlist path for ffuf subdomain brute-force (optional but recommended)."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help="Dashboard refresh interval in seconds (default: 30)."
    )
    parser.add_argument(
        "--skip-nikto",
        action="store_true",
        help="Skip Nikto scanning (can be heavy)."
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host/IP for the web UI (default: 0.0.0.0)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8342,
        help="Port for the web UI (default: 8342)."
    )
    parser.add_argument(
        "--skip-setup",
        action="store_true",
        help="Skip the first-run setup wizard (not recommended for first run)."
    )
    parser.add_argument(
        "--https",
        action="store_true",
        help="Enable HTTPS with a self-signed certificate (auto-generated if cert/key not provided)."
    )
    parser.add_argument(
        "--cert",
        help="Path to SSL certificate file (for HTTPS). If not provided with --https, a self-signed cert will be generated."
    )
    parser.add_argument(
        "--key",
        help="Path to SSL private key file (for HTTPS). If not provided with --https, a self-signed key will be generated."
    )
    parser.add_argument(
        "--tool-workers",
        type=int,
        metavar="N",
        help=(f"How many copies of each tool may run at once (default {DEFAULT_TOOL_WORKERS}, max "
              f"{MAX_TOOL_WORKERS}). httpx, nuclei and nikto also split a host batch across this many "
              "processes. Saved to the config, so it sticks for later runs.")
    )

    args = parser.parse_args()

    ensure_dirs()
    
    # Initialize database and migrate old data if needed
    ensure_database()
    
    # Check if this is the first run and run setup wizard
    cfg = get_config()

    if args.tool_workers is not None:
        success, message, cfg = update_config_settings({"default_tool_workers": args.tool_workers})
        log(message if not success else f"Workers per tool set to {cfg.get('default_tool_workers')}.")
        if not success:
            sys.exit(1)

    setup_completed = cfg.get("setup_completed", False)
    
    if not setup_completed and not args.skip_setup:
        # Only run setup wizard in interactive mode
        if sys.stdin.isatty():
            try:
                run_setup_wizard()
                # Reload config after setup
                cfg = get_config()
            except KeyboardInterrupt:
                print("\n\nSetup interrupted by user.")
                print("You can run the setup wizard again next time,")
                print("or configure settings through the web UI.")
                print("\nContinuing with default settings...\n")
                # Mark setup as completed so we don't prompt again
                cfg["setup_completed"] = True
                save_config(cfg)
        else:
            log("First run detected but running in non-interactive mode.")
            log("Skipping setup wizard. You can configure settings through the web UI.")
            cfg["setup_completed"] = True
            save_config(cfg)
    
    ensure_required_tools()

    if args.domain:
        cfg = get_config()
        targets = expand_wildcard_targets(args.domain, cfg)
        if not targets:
            cleaned = _sanitize_domain_input(args.domain)
            if cleaned.endswith(".*"):
                log("Wildcard TLD requested but no TLDs are configured. Update wildcard settings in the web UI.")
            else:
                log("No valid targets resolved from input.")
            return
        for target in targets:
            log(f"Running single pipeline execution for {target}.")
            try:
                run_pipeline(target, args.wordlist, skip_nikto=args.skip_nikto, interval=args.interval)
            except KeyboardInterrupt:
                log("Interrupted by user.")
                return
            except Exception as e:
                log(f"Fatal error while processing {target}: {e}")
        return

    log("Launching Recon Command Center web server.")
    
    # Ensure admin account exists before starting server
    if not prompt_admin_creation():
        log("ERROR: Cannot start web server without an admin account.")
        return
    
    run_server(args.host, args.port, args.interval, use_https=args.https, cert_file=args.cert, key_file=args.key)
