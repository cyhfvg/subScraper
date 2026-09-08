"""Fragment 07_start_dynamic_mode_worker.py. Loaded into the main module namespace."""
def start_dynamic_mode_worker() -> None:
    """Start the dynamic mode worker thread."""
    global DYNAMIC_MODE_THREAD
    
    if not PSUTIL_AVAILABLE:
        log("Dynamic mode disabled: psutil not available")
        return
    
    with DYNAMIC_MODE_LOCK:
        already_running = DYNAMIC_MODE_THREAD and DYNAMIC_MODE_THREAD.is_alive()
    
    if already_running:
        return
    
    thread = threading.Thread(target=dynamic_mode_worker_loop, name="dynamic-mode", daemon=True)
    thread.start()
    
    with DYNAMIC_MODE_LOCK:
        DYNAMIC_MODE_THREAD = thread
    
    log("Dynamic mode worker initialized.")


def stop_dynamic_mode_worker() -> None:
    """Stop the dynamic mode worker thread."""
    global DYNAMIC_MODE_THREAD
    
    with DYNAMIC_MODE_LOCK:
        if DYNAMIC_MODE_THREAD and DYNAMIC_MODE_THREAD.is_alive():
            # Thread will stop on next iteration when it checks DYNAMIC_MODE_ENABLED
            DYNAMIC_MODE_THREAD = None
            log("Dynamic mode worker stopped.")


def get_dynamic_mode_status() -> Dict[str, Any]:
    """Get current dynamic mode status."""
    with DYNAMIC_MODE_LOCK:
        return {
            "enabled": DYNAMIC_MODE_ENABLED,
            "base_jobs": DYNAMIC_MODE_BASE_JOBS,
            "max_jobs": DYNAMIC_MODE_MAX_JOBS,
            "current_jobs": MAX_RUNNING_JOBS,
            "cpu_threshold": DYNAMIC_MODE_CPU_THRESHOLD,
            "memory_threshold": DYNAMIC_MODE_MEMORY_THRESHOLD,
            "worker_active": DYNAMIC_MODE_THREAD and DYNAMIC_MODE_THREAD.is_alive() if DYNAMIC_MODE_THREAD else False,
        }


# ================== BACKUP & RESTORE SYSTEM ==================


def create_backup(name: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """
    Create a full backup of all recon data.
    Returns (success, message, backup_filename)
    """
    try:
        ensure_dirs()
        
        # Generate backup filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if name:
            backup_name = f"backup_{name}_{timestamp}.tar.gz"
        else:
            backup_name = f"backup_{timestamp}.tar.gz"
        
        backup_path = BACKUPS_DIR / backup_name
        
        # Create tarball
        with tarfile.open(backup_path, "w:gz") as tar:
            # Add state file
            if STATE_FILE.exists():
                tar.add(STATE_FILE, arcname="state.json")
            
            # Add config file
            if CONFIG_FILE.exists():
                tar.add(CONFIG_FILE, arcname="config.json")
            
            # Add monitors file
            if MONITORS_FILE.exists():
                tar.add(MONITORS_FILE, arcname="monitors.json")
            
            # Add system resources file
            if SYSTEM_RESOURCE_FILE.exists():
                tar.add(SYSTEM_RESOURCE_FILE, arcname="system_resources.json")
            
            # Add completed jobs file
            if COMPLETED_JOBS_FILE.exists():
                tar.add(COMPLETED_JOBS_FILE, arcname="completed_jobs.json")
            
            # Add history directory
            if HISTORY_DIR.exists():
                tar.add(HISTORY_DIR, arcname="history")
            
            # Add screenshots directory (if not too large)
            if SCREENSHOTS_DIR.exists():
                tar.add(SCREENSHOTS_DIR, arcname="screenshots")
        
        backup_size = backup_path.stat().st_size
        size_mb = backup_size / (1024 * 1024)
        
        log(f"✅ Backup created: {backup_name} ({size_mb:.2f} MB)")
        return True, f"Backup created successfully: {backup_name} ({size_mb:.2f} MB)", backup_name
    except Exception as exc:
        log(f"❌ Backup creation failed: {exc}")
        return False, f"Backup failed: {str(exc)}", None


def restore_backup(backup_filename: str) -> Tuple[bool, str]:
    """
    Restore data from a backup file.
    Returns (success, message)
    """
    try:
        backup_path = BACKUPS_DIR / backup_filename
        if not backup_path.exists():
            return False, f"Backup file not found: {backup_filename}"
        
        # Create temporary restore directory
        temp_restore = DATA_DIR / ".restore_temp"
        temp_restore.mkdir(exist_ok=True)
        
        # Extract backup
        with tarfile.open(backup_path, "r:gz") as tar:
            tar.extractall(temp_restore)
        
        # Acquire lock before restoring
        acquire_lock()
        try:
            # Restore files
            restored_files = []
            
            if (temp_restore / "state.json").exists():
                shutil.copy2(temp_restore / "state.json", STATE_FILE)
                restored_files.append("state.json")
            
            if (temp_restore / "config.json").exists():
                shutil.copy2(temp_restore / "config.json", CONFIG_FILE)
                restored_files.append("config.json")
            
            if (temp_restore / "monitors.json").exists():
                shutil.copy2(temp_restore / "monitors.json", MONITORS_FILE)
                restored_files.append("monitors.json")
            
            if (temp_restore / "system_resources.json").exists():
                shutil.copy2(temp_restore / "system_resources.json", SYSTEM_RESOURCE_FILE)
                restored_files.append("system_resources.json")
            
            if (temp_restore / "completed_jobs.json").exists():
                shutil.copy2(temp_restore / "completed_jobs.json", COMPLETED_JOBS_FILE)
                restored_files.append("completed_jobs.json")
            
            if (temp_restore / "history").exists():
                if HISTORY_DIR.exists():
                    shutil.rmtree(HISTORY_DIR)
                shutil.copytree(temp_restore / "history", HISTORY_DIR)
                restored_files.append("history/")
            
            if (temp_restore / "screenshots").exists():
                if SCREENSHOTS_DIR.exists():
                    shutil.rmtree(SCREENSHOTS_DIR)
                shutil.copytree(temp_restore / "screenshots", SCREENSHOTS_DIR)
                restored_files.append("screenshots/")
        finally:
            release_lock()
        
        # Clean up temp directory
        shutil.rmtree(temp_restore, ignore_errors=True)
        
        # Reload configuration
        load_config()
        load_monitors_state()
        load_system_resource_state()
        
        # Reload completed jobs
        global COMPLETED_JOBS
        loaded_jobs = load_completed_jobs()
        with JOB_LOCK:
            COMPLETED_JOBS.clear()
            COMPLETED_JOBS.update(loaded_jobs)
        
        log(f"✅ Backup restored: {backup_filename} ({len(restored_files)} items)")
        return True, f"Backup restored successfully: {', '.join(restored_files)}"
    except Exception as exc:
        log(f"❌ Backup restoration failed: {exc}")
        return False, f"Restore failed: {str(exc)}"


def list_backups() -> List[Dict[str, Any]]:
    """List all available backups."""
    try:
        ensure_dirs()
        backups = []
        
        for backup_file in sorted(BACKUPS_DIR.glob("backup_*.tar.gz"), reverse=True):
            try:
                stat = backup_file.stat()
                backups.append({
                    "filename": backup_file.name,
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "created_timestamp": stat.st_mtime,
                })
            except Exception:
                continue
        
        return backups
    except Exception as exc:
        log(f"Error listing backups: {exc}")
        return []


def delete_backup(backup_filename: str) -> Tuple[bool, str]:
    """Delete a specific backup file."""
    try:
        backup_path = BACKUPS_DIR / backup_filename
        if not backup_path.exists():
            return False, f"Backup file not found: {backup_filename}"
        
        backup_path.unlink()
        log(f"🗑️  Backup deleted: {backup_filename}")
        return True, f"Backup deleted: {backup_filename}"
    except Exception as exc:
        log(f"❌ Backup deletion failed: {exc}")
        return False, f"Delete failed: {str(exc)}"


def cleanup_old_backups() -> int:
    """Delete old backups keeping only the most recent N backups. Returns number deleted."""
    try:
        backups = list_backups()
        if len(backups) <= AUTO_BACKUP_MAX_COUNT:
            return 0
        
        # Delete oldest backups
        to_delete = backups[AUTO_BACKUP_MAX_COUNT:]
        deleted_count = 0
        
        for backup in to_delete:
            success, _ = delete_backup(backup["filename"])
            if success:
                deleted_count += 1
        
        if deleted_count > 0:
            log(f"🗑️  Cleaned up {deleted_count} old backup(s)")
        
        return deleted_count
    except Exception as exc:
        log(f"Error cleaning up backups: {exc}")
        return 0


def auto_backup_worker_loop() -> None:
    """Background worker that creates automatic backups on a schedule."""
    global LAST_BACKUP_TIME
    
    log("Auto-backup worker started.")
    
    # Set initial backup time to now to avoid immediate backup on start
    LAST_BACKUP_TIME = time.time()
    
    while True:
        try:
            if not AUTO_BACKUP_ENABLED:
                time.sleep(60)  # Check every minute if disabled
                continue
            
            current_time = time.time()
            time_since_backup = current_time - LAST_BACKUP_TIME
            
            if time_since_backup >= AUTO_BACKUP_INTERVAL:
                log("⏰ Auto-backup triggered")
                success, message, filename = create_backup("auto")
                
                if success:
                    LAST_BACKUP_TIME = current_time
                    # Clean up old backups
                    cleanup_old_backups()
                else:
                    log(f"Auto-backup failed: {message}")
            
            # Sleep for a short interval to check again
            time.sleep(60)
        except Exception as exc:
            log(f"Error in auto-backup worker: {exc}")
            time.sleep(60)


def start_auto_backup_worker() -> None:
    """Start the auto-backup worker thread."""
    global AUTO_BACKUP_THREAD
    
    with AUTO_BACKUP_LOCK:
        already_running = AUTO_BACKUP_THREAD and AUTO_BACKUP_THREAD.is_alive()
    
    if already_running:
        return
    
    thread = threading.Thread(target=auto_backup_worker_loop, name="auto-backup", daemon=True)
    thread.start()
    
    with AUTO_BACKUP_LOCK:
        AUTO_BACKUP_THREAD = thread
    
    log("Auto-backup worker initialized.")


def stop_auto_backup_worker() -> None:
    """Stop the auto-backup worker thread."""
    global AUTO_BACKUP_THREAD
    
    with AUTO_BACKUP_LOCK:
        if AUTO_BACKUP_THREAD and AUTO_BACKUP_THREAD.is_alive():
            AUTO_BACKUP_THREAD = None
            log("Auto-backup worker stopped.")


def get_auto_backup_status() -> Dict[str, Any]:
    """Get current auto-backup status."""
    with AUTO_BACKUP_LOCK:
        next_backup_time = LAST_BACKUP_TIME + AUTO_BACKUP_INTERVAL if AUTO_BACKUP_ENABLED else None
        return {
            "enabled": AUTO_BACKUP_ENABLED,
            "interval_seconds": AUTO_BACKUP_INTERVAL,
            "max_count": AUTO_BACKUP_MAX_COUNT,
            "last_backup_timestamp": LAST_BACKUP_TIME,
            "next_backup_timestamp": next_backup_time,
            "next_backup": datetime.fromtimestamp(next_backup_time, tz=timezone.utc).isoformat() if next_backup_time else None,
            "worker_active": AUTO_BACKUP_THREAD and AUTO_BACKUP_THREAD.is_alive() if AUTO_BACKUP_THREAD else False,
        }


# ================== FILE CLEANUP SYSTEM ==================

# Cleanup system configuration
AUTO_CLEANUP_ENABLED = False
CLEANUP_SCAN_RESULTS_DAYS = 30
CLEANUP_TEMP_FILES_HOURS = 24
CLEANUP_INTERVAL = 3600
LAST_CLEANUP_TIME = 0.0
CLEANUP_LOCK = threading.Lock()
CLEANUP_THREAD: Optional[threading.Thread] = None
CLEANUP_STOP_EVENT = threading.Event()


def cleanup_temporary_files() -> int:
    """
    Clean up temporary files (.tmp.*, .backup) older than configured hours.
    Returns number of files deleted.
    """
    try:
        ensure_dirs()
        deleted_count = 0
        cutoff_time = time.time() - (CLEANUP_TEMP_FILES_HOURS * 3600)
        
        # Patterns for temporary files
        temp_patterns = [
            "*.tmp.*",
            "*.backup",
            ".restore_temp"
        ]
        
        for pattern in temp_patterns:
            for temp_file in DATA_DIR.glob(pattern):
                try:
                    # Skip if it's a directory (handle .restore_temp separately)
                    if temp_file.is_dir():
                        # Only remove .restore_temp if it's old
                        if temp_file.name == ".restore_temp":
                            file_mtime = temp_file.stat().st_mtime
                            if file_mtime < cutoff_time:
                                shutil.rmtree(temp_file, ignore_errors=True)
                                deleted_count += 1
                                log(f"🗑️  Removed old temp directory: {temp_file.name}")
                        continue
                    
                    # Check file age
                    file_mtime = temp_file.stat().st_mtime
                    if file_mtime < cutoff_time:
                        temp_file.unlink()
                        deleted_count += 1
                        log(f"🗑️  Removed old temp file: {temp_file.name}")
                except Exception as e:
                    log(f"Warning: Could not remove temp file {temp_file}: {e}")
        
        if deleted_count > 0:
            log(f"✓ Cleaned up {deleted_count} temporary file(s)")
        
        return deleted_count
    except Exception as exc:
        log(f"Error cleaning up temporary files: {exc}")
        return 0


def cleanup_old_scan_results() -> int:
    """
    Clean up old scan result files (nuclei_*.json, nikto_*.json, httpx_*.json, ffuf_*.json)
    older than configured days. Returns number of files deleted.
    """
    try:
        ensure_dirs()
        deleted_count = 0
        cutoff_time = time.time() - (CLEANUP_SCAN_RESULTS_DAYS * 86400)
        
        # Patterns for scan result files
        scan_patterns = [
            "nuclei_*.json",
            "nikto_*.json",
            "httpx_*.json",
            "ffuf_*.json"
        ]
        
        for pattern in scan_patterns:
            for scan_file in DATA_DIR.glob(pattern):
                try:
                    # Skip if it's not a file
                    if not scan_file.is_file():
                        continue
                    
                    # Check file age
                    file_mtime = scan_file.stat().st_mtime
                    if file_mtime < cutoff_time:
                        scan_file.unlink()
                        deleted_count += 1
                        log(f"🗑️  Removed old scan result: {scan_file.name}")
                except Exception as e:
                    log(f"Warning: Could not remove scan file {scan_file}: {e}")
        
        if deleted_count > 0:
            log(f"✓ Cleaned up {deleted_count} old scan result file(s)")
        
        return deleted_count
    except Exception as exc:
        log(f"Error cleaning up scan results: {exc}")
        return 0


def run_cleanup() -> Dict[str, int]:
    """Run all cleanup tasks and return statistics."""
    stats = {
        "temp_files": 0,
        "scan_results": 0,
        "backups": 0
    }
    
    try:
        # Clean up temporary files
        stats["temp_files"] = cleanup_temporary_files()
        
        # Clean up old scan results
        stats["scan_results"] = cleanup_old_scan_results()
        
        # Clean up old backups
        stats["backups"] = cleanup_old_backups()
        
        total = sum(stats.values())
        if total > 0:
            log(f"✓ Cleanup completed: {stats['temp_files']} temp files, "
                f"{stats['scan_results']} scan results, {stats['backups']} backups removed")
        
        return stats
    except Exception as exc:
        log(f"Error during cleanup: {exc}")
        return stats
