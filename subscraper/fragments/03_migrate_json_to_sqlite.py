"""Fragment 03_migrate_json_to_sqlite.py. Loaded into the main module namespace."""
def migrate_json_to_sqlite() -> None:
    """Migrate all JSON data to SQLite database."""
    log("Starting migration from JSON files to SQLite...")
    
    # Migrate config
    if CONFIG_FILE.exists() and not check_migration_done("config_json"):
        log("Migrating config.json...")
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for key, value in config_data.items():
                cursor.execute(
                    "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), now)
                )
            
            db.commit()
            mark_migration_done("config_json")
            log("✓ Config migration completed.")
        except Exception as e:
            log(f"Error migrating config.json: {e}")
    
    # Migrate state (targets and subdomains)
    if STATE_FILE.exists() and not check_migration_done("state_json"):
        log("Migrating state.json...")
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state_data = json.load(f)
            
            targets = state_data.get("targets", {})
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for domain, target_data in targets.items():
                subdomains = target_data.get("subdomains", {})
                flags = target_data.get("flags", {})
                options = target_data.get("options", {})
                
                # Insert target
                cursor.execute(
                    """INSERT OR REPLACE INTO targets 
                       (domain, data, flags, options, created_at, updated_at) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (domain, "{}", json.dumps(flags), json.dumps(options), now, now)
                )
                
                # Insert subdomains
                for subdomain, sub_data in subdomains.items():
                    cursor.execute(
                        """INSERT OR REPLACE INTO subdomains 
                           (domain, subdomain, data, created_at, updated_at) 
                           VALUES (?, ?, ?, ?, ?)""",
                        (domain, subdomain, json.dumps(sub_data), now, now)
                    )
            
            db.commit()
            mark_migration_done("state_json")
            log(f"✓ State migration completed ({len(targets)} targets).")
        except Exception as e:
            log(f"Error migrating state.json: {e}")
    
    # Migrate completed jobs
    if COMPLETED_JOBS_FILE.exists() and not check_migration_done("completed_jobs_json"):
        log("Migrating completed_jobs.json...")
        try:
            with open(COMPLETED_JOBS_FILE, "r", encoding="utf-8") as f:
                jobs_data = json.load(f)
            
            jobs = jobs_data.get("jobs", {})
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for job_key, job_data in jobs.items():
                domain = job_key.rsplit("_", 1)[0] if "_" in job_key else job_key
                completed_at = job_data.get("completed_at", now)
                
                cursor.execute(
                    """INSERT OR REPLACE INTO completed_jobs 
                       (job_key, domain, data, completed_at, created_at) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (job_key, domain, json.dumps(job_data), completed_at, now)
                )
            
            db.commit()
            mark_migration_done("completed_jobs_json")
            log(f"✓ Completed jobs migration completed ({len(jobs)} jobs).")
        except Exception as e:
            log(f"Error migrating completed_jobs.json: {e}")
    
    # Migrate monitors
    if MONITORS_FILE.exists() and not check_migration_done("monitors_json"):
        log("Migrating monitors.json...")
        try:
            with open(MONITORS_FILE, "r", encoding="utf-8") as f:
                monitors_data = json.load(f)
            
            monitors = monitors_data.get("monitors", {})
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            for monitor_id, monitor_data in monitors.items():
                name = monitor_data.get("name", "")
                url = monitor_data.get("url", "")
                created_at = monitor_data.get("created_at", now)
                
                cursor.execute(
                    """INSERT OR REPLACE INTO monitors 
                       (id, name, url, data, created_at, updated_at) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (monitor_id, name, url, json.dumps(monitor_data), created_at, now)
                )
            
            db.commit()
            mark_migration_done("monitors_json")
            log(f"✓ Monitors migration completed ({len(monitors)} monitors).")
        except Exception as e:
            log(f"Error migrating monitors.json: {e}")
    
    # Migrate history files
    if HISTORY_DIR.exists() and not check_migration_done("history_jsonl"):
        log("Migrating history/*.jsonl files...")
        try:
            db = get_db()
            cursor = db.cursor()
            now = datetime.now(timezone.utc).isoformat()
            total_entries = 0
            
            for history_file in HISTORY_DIR.glob("*.jsonl"):
                domain = history_file.stem
                
                with history_file.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            timestamp = entry.get("ts", now)
                            source = entry.get("source", "system")
                            text = entry.get("text", "")
                            
                            cursor.execute(
                                """INSERT INTO history 
                                   (domain, timestamp, source, text, created_at) 
                                   VALUES (?, ?, ?, ?, ?)""",
                                (domain, timestamp, source, text, now)
                            )
                            total_entries += 1
                        except json.JSONDecodeError:
                            continue
            
            db.commit()
            mark_migration_done("history_jsonl")
            log(f"✓ History migration completed ({total_entries} entries).")
        except Exception as e:
            log(f"Error migrating history files: {e}")
    
    log("Migration from JSON to SQLite completed successfully!")


def run_schema_migrations() -> None:
    """Run schema migrations to add new columns to existing tables."""
    db = get_db()
    cursor = db.cursor()
    
    # Migration: Add interesting and comments columns to subdomains table
    if not check_migration_done("add_subdomain_interesting_comments"):
        log("Running migration: add_subdomain_interesting_comments")
        try:
            # Check if columns already exist
            cursor.execute("PRAGMA table_info(subdomains)")
            columns = {row[1] for row in cursor.fetchall()}
            
            if "interesting" not in columns:
                cursor.execute("ALTER TABLE subdomains ADD COLUMN interesting INTEGER")
                log("  ✓ Added 'interesting' column to subdomains table")
            
            if "comments" not in columns:
                cursor.execute("ALTER TABLE subdomains ADD COLUMN comments TEXT")
                log("  ✓ Added 'comments' column to subdomains table")
            
            db.commit()
            mark_migration_done("add_subdomain_interesting_comments")
            log("✓ Migration add_subdomain_interesting_comments completed")
        except Exception as e:
            log(f"Error in migration add_subdomain_interesting_comments: {e}")
    
    # Migration: Add comments column to targets table
    if not check_migration_done("add_target_comments"):
        log("Running migration: add_target_comments")
        try:
            cursor.execute("PRAGMA table_info(targets)")
            columns = {row[1] for row in cursor.fetchall()}
            
            if "comments" not in columns:
                cursor.execute("ALTER TABLE targets ADD COLUMN comments TEXT")
                log("  ✓ Added 'comments' column to targets table")
            
            db.commit()
            mark_migration_done("add_target_comments")
            log("✓ Migration add_target_comments completed")
        except Exception as e:
            log(f"Error in migration add_target_comments: {e}")
    
    # Migration: Add performance indexes for summary queries
    if not check_migration_done("add_performance_indexes"):
        log("Running migration: add_performance_indexes")
        try:
            # Index for filtering subdomains by interesting flag
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_subdomains_domain_interesting 
                ON subdomains(domain, interesting) WHERE interesting IS NOT NULL
            """)
            log("  ✓ Added index on subdomains(domain, interesting)")
            
            # Index for targets updated_at for last_updated queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_targets_updated_at 
                ON targets(updated_at DESC)
            """)
            log("  ✓ Added index on targets(updated_at)")
            
            db.commit()
            mark_migration_done("add_performance_indexes")
            log("✓ Migration add_performance_indexes completed")
        except Exception as e:
            log(f"Error in migration add_performance_indexes: {e}")
    
    # Migration: Add additional indexes for JOIN optimization and large dataset handling
    if not check_migration_done("add_join_optimization_indexes"):
        log("Running migration: add_join_optimization_indexes")
        try:
            # Composite index for subdomains JOIN - covers domain lookup
            # This is critical for the optimized JOIN queries in load_state() and build_state_payload_summary()
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_subdomains_domain_subdomain 
                ON subdomains(domain, subdomain)
            """)
            log("  ✓ Added composite index on subdomains(domain, subdomain)")
            
            # Index for completed_jobs domain lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_completed_jobs_domain_completed 
                ON completed_jobs(domain, completed_at DESC)
            """)
            log("  ✓ Added index on completed_jobs(domain, completed_at)")
            
            # Index for history timestamp ordering (for paginated queries)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_domain_timestamp 
                ON history(domain, timestamp DESC)
            """)
            log("  ✓ Added index on history(domain, timestamp)")
            
            db.commit()
            mark_migration_done("add_join_optimization_indexes")
            log("✓ Migration add_join_optimization_indexes completed")
        except Exception as e:
            log(f"Error in migration add_join_optimization_indexes: {e}")



def ensure_database() -> None:
    """Ensure database is initialized and migrated."""
    init_database()
    migrate_json_to_sqlite()
    run_schema_migrations()


def atomic_write_json(filepath: Path, data: Dict[str, Any], indent: int = 2) -> None:
    """
    Atomically write JSON data to a file using a temporary file.
    This prevents corruption if the process crashes during write.
    Includes proper error handling for race conditions and filesystem issues.
    """
    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Create temp file in same directory to ensure same filesystem
    # This is important for atomic rename to work properly
    tmp_path = filepath.with_suffix(f".tmp.{os.getpid()}")
    
    try:
        # Write data to temporary file
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, sort_keys=True)
            # Sync to disk (flush OS buffers) while file is still open
            # This ensures data is written before rename
            try:
                f.flush()
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                # fsync may not be supported on all platforms/filesystems
                pass
        
        # Atomic rename - this is the critical operation
        # On most systems, this is atomic if both files are on same filesystem
        try:
            tmp_path.replace(filepath)
        except OSError as e:
            # If replace fails, try alternative methods
            log(f"Warning: atomic replace failed for {filepath}: {e}. Trying fallback...")
            
            # Try direct rename (less safe but may work)
            if filepath.exists():
                backup_path = filepath.with_suffix(".backup")
                try:
                    shutil.copy2(filepath, backup_path)
                except Exception:
                    pass
            
            shutil.move(str(tmp_path), str(filepath))
    
    except Exception as e:
        # Clean up temp file on any error
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise RuntimeError(f"Failed to write {filepath}: {e}") from e
    
    finally:
        # Ensure temp file is cleaned up even if something went wrong
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                # Don't fail if cleanup fails
                pass


def atomic_write_text(filepath: Path, content: str) -> None:
    """
    Atomically write text content to a file using a temporary file.
    Similar to atomic_write_json but for text files.
    """
    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Create temp file in same directory to ensure same filesystem
    tmp_path = filepath.with_suffix(f".tmp.{os.getpid()}")
    
    try:
        # Write content to temporary file
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            # Sync to disk while file is still open
            try:
                f.flush()
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        
        # Atomic rename
        try:
            tmp_path.replace(filepath)
        except OSError as e:
            log(f"Warning: atomic replace failed for {filepath}: {e}. Trying fallback...")
            if filepath.exists():
                backup_path = filepath.with_suffix(".backup")
                try:
                    shutil.copy2(filepath, backup_path)
                except Exception:
                    pass
            shutil.move(str(tmp_path), str(filepath))
    
    except Exception as e:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise RuntimeError(f"Failed to write {filepath}: {e}") from e
    
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


# ================== AUTHENTICATION & USER MANAGEMENT ==================

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Store salt + hash as hex
    return salt.hex() + pwd_hash.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        # Extract salt (first 64 hex chars = 32 bytes)
        salt = bytes.fromhex(stored_hash[:64])
        stored_pwd_hash = stored_hash[64:]
        # Hash the input password with the same salt
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        # Compare in constant time
        return hmac.compare_digest(pwd_hash.hex(), stored_pwd_hash)
    except (ValueError, IndexError):
        return False


def create_user(username: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
    """Create a new user."""
    if not username or not password:
        return False, "Username and password are required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    # Validate username (alphanumeric, underscore, hyphen only)
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"
    
    db = get_db()
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    try:
        password_hash = hash_password(password)
        cursor.execute(
            """INSERT INTO users (username, password_hash, is_admin, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (username.lower(), password_hash, 1 if is_admin else 0, now, now)
        )
        db.commit()
        log(f"User '{username}' created successfully (admin={is_admin})")
        return True, f"User '{username}' created successfully"
    except sqlite3.IntegrityError:
        return False, f"Username '{username}' already exists"
    except Exception as e:
        log(f"Error creating user: {e}")
        return False, f"Error creating user: {str(e)}"
