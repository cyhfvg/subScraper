"""Fragment 02_track_timeout_error.py. Loaded into the main module namespace."""
def track_timeout_error(domain: str, error: Exception, job_domain: Optional[str] = None) -> None:
    """
    Track timeout/rate-limit errors for a domain and automatically adjust rate limiting.
    """
    global GLOBAL_RATE_LIMIT_DELAY
    
    if not is_rate_limit_error(error):
        return
    
    with TIMEOUT_TRACKER_LOCK:
        if domain not in TIMEOUT_TRACKER:
            TIMEOUT_TRACKER[domain] = {
                "errors": 0,
                "last_error_time": 0.0,
                "backoff_delay": 0.0,
            }
        
        tracker = TIMEOUT_TRACKER[domain]
        current_time = time.time()
        
        # Reset counter if last error was more than 5 minutes ago
        if current_time - tracker["last_error_time"] > 300:
            tracker["errors"] = 0
            tracker["backoff_delay"] = 0.0
        
        tracker["errors"] += 1
        tracker["last_error_time"] = current_time
        
        # If we've hit the threshold, increase rate limiting
        if tracker["errors"] >= TIMEOUT_ERROR_THRESHOLD:
            old_delay = GLOBAL_RATE_LIMIT_DELAY
            new_delay = min(old_delay + TIMEOUT_BACKOFF_INCREMENT, MAX_AUTO_BACKOFF_DELAY)
            
            if new_delay > old_delay:
                GLOBAL_RATE_LIMIT_DELAY = new_delay
                tracker["backoff_delay"] = new_delay
                
                log_msg = (
                    f"⚠️  Rate limiting detected for {domain} ({tracker['errors']} errors). "
                    f"Automatically increasing global rate limit from {old_delay:.1f}s to {new_delay:.1f}s. "
                    f"Error: {str(error)[:100]}"
                )
                log(log_msg)
                
                if job_domain:
                    job_log_append(
                        job_domain,
                        f"Rate limiting detected. Slowing down requests (delay now {new_delay:.1f}s)",
                        source="rate-limiter"
                    )
                
                # Reset error counter after adjustment
                tracker["errors"] = 0
            else:
                log_msg = (
                    f"⚠️  Rate limiting detected for {domain} but already at max backoff "
                    f"({GLOBAL_RATE_LIMIT_DELAY:.1f}s). Error: {str(error)[:100]}"
                )
                log(log_msg)
                
                if job_domain:
                    job_log_append(
                        job_domain,
                        f"Rate limiting detected (already at max delay {GLOBAL_RATE_LIMIT_DELAY:.1f}s)",
                        source="rate-limiter"
                    )


def apply_rate_limit() -> None:
    """
    Apply global rate limiting by enforcing minimum delay between tool calls.
    """
    global RATE_LIMIT_LAST_CALL
    if GLOBAL_RATE_LIMIT_DELAY <= 0:
        return
    with RATE_LIMIT_LOCK:
        now = time.time()
        elapsed = now - RATE_LIMIT_LAST_CALL
        if elapsed < GLOBAL_RATE_LIMIT_DELAY:
            sleep_time = GLOBAL_RATE_LIMIT_DELAY - elapsed
            time.sleep(sleep_time)
        RATE_LIMIT_LAST_CALL = time.time()


JOB_CONTROLS: Dict[str, JobControl] = {}
JOB_CONTROL_LOCK = threading.Lock()
ACTIVE_PAUSED_JOBS: set = set()
MONITOR_LOCK = threading.Lock()
MONITOR_STATE: Dict[str, Dict[str, Any]] = {}
MONITOR_THREAD: Optional[threading.Thread] = None
MONITOR_POLL_INTERVAL = 10
DEFAULT_MONITOR_INTERVAL = 300
MAX_MONITOR_ENTRIES = 200

# System Resource Monitoring
SYSTEM_RESOURCE_LOCK = threading.Lock()
SYSTEM_RESOURCE_STATE: Dict[str, Any] = {}
SYSTEM_RESOURCE_THREAD: Optional[threading.Thread] = None
SYSTEM_RESOURCE_POLL_INTERVAL = 5  # Poll every 5 seconds
SYSTEM_RESOURCE_HISTORY_SIZE = 720  # Keep 1 hour of history at 5-second intervals
SYSTEM_RESOURCE_HISTORY: List[Dict[str, Any]] = []
SYSTEM_RESOURCE_FILE = DATA_DIR / "system_resources.json"


# ================== UTILITIES =======================

def log(msg: str, level: str = "info") -> None:
    """写一条应用日志.

    Args:
        msg: 日志正文.
        level: debug/info/warning/error/critical, 默认 info.
    Returns:
        None.
    Raises:
        无. 未知 level 回退为 info.
    Example:
        log("scan started", "info")
    """
    logger = logging.getLogger("subscraper")
    normalized = (level or "info").lower()
    log_fn = getattr(logger, normalized, logger.info)
    log_fn(msg)
    if not logger.handlers:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts} UTC] {msg}")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)


# ================== SQLite DATABASE ====================

def get_db() -> sqlite3.Connection:
    """
    Get a thread-safe database connection with performance optimizations.
    
    Optimizations:
    - WAL mode for better concurrency
    - Increased cache size for large datasets
    - Optimized synchronous mode for speed
    """
    global DB_CONN
    with DB_LOCK:
        if DB_CONN is None:
            ensure_dirs()
            # Set isolation_level to None for autocommit mode to prevent
            # "cannot start a transaction within a transaction" errors
            DB_CONN = sqlite3.connect(str(DB_FILE), check_same_thread=False, isolation_level=None)
            DB_CONN.row_factory = sqlite3.Row
            
            # Enable WAL mode for better concurrency
            DB_CONN.execute("PRAGMA journal_mode=WAL")
            DB_CONN.execute("PRAGMA foreign_keys=ON")
            
            # OPTIMIZATION: Performance tuning for large datasets (10,000+ rows)
            # Increase cache size to 64MB (default is ~2MB)
            # This significantly improves query performance with large data
            DB_CONN.execute("PRAGMA cache_size=-64000")  # Negative = KB
            
            # Set synchronous to NORMAL for better performance (WAL makes this safe)
            # FULL is safest but slower, NORMAL is good balance with WAL
            DB_CONN.execute("PRAGMA synchronous=NORMAL")
            
            # Enable memory-mapped I/O for faster reads (256MB mmap)
            DB_CONN.execute("PRAGMA mmap_size=268435456")
            
            # Set temp store to memory for faster operations
            DB_CONN.execute("PRAGMA temp_store=MEMORY")
        return DB_CONN


def init_database() -> None:
    """Initialize the SQLite database schema."""
    db = get_db()
    cursor = db.cursor()
    
    # Config table - stores key-value configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Targets table - stores domain targets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            domain TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            flags TEXT,
            options TEXT,
            comments TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Subdomains table - stores subdomain data for each target
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            data TEXT NOT NULL,
            interesting INTEGER,
            comments TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(domain, subdomain),
            FOREIGN KEY (domain) REFERENCES targets(domain) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_subdomains_domain 
        ON subdomains(domain)
    """)
    
    # Completed jobs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS completed_jobs (
            job_key TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            data TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_completed_jobs_domain 
        ON completed_jobs(domain)
    """)
    
    # Monitors table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # System resources table - stores resource snapshots
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_system_resources_timestamp 
        ON system_resources(timestamp DESC)
    """)
    
    # History table - stores per-domain event history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_history_domain 
        ON history(domain, timestamp DESC)
    """)
    
    # Migration tracking table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_name TEXT UNIQUE NOT NULL,
            completed_at TEXT NOT NULL
        )
    """)
    
    # Users table - stores authentication credentials
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_username 
        ON users(username)
    """)
    
    # Scoped API keys for the bug bounty agent API
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            scopes TEXT NOT NULL,
            programs TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            last_used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_agent_api_keys_key_id 
        ON agent_api_keys(key_id)
    """)
    
    # Bug bounty programs - full scope definitions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS programs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            platform TEXT,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_programs_updated_at 
        ON programs(updated_at DESC)
    """)
    
    db.commit()
    log("Database schema initialized successfully.")


def check_migration_done(migration_name: str) -> bool:
    """Check if a migration has already been completed."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT 1 FROM migrations WHERE migration_name = ?",
        (migration_name,)
    )
    return cursor.fetchone() is not None


def mark_migration_done(migration_name: str) -> None:
    """Mark a migration as completed."""
    db = get_db()
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT OR IGNORE INTO migrations (migration_name, completed_at) VALUES (?, ?)",
        (migration_name, now)
    )
    db.commit()
