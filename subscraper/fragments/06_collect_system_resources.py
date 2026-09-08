"""Fragment 06_collect_system_resources.py. Loaded into the main module namespace."""
def collect_system_resources() -> Dict[str, Any]:
    """
    Collect current system resource metrics.
    Returns comprehensive data about CPU, memory, disk, network, and process usage.
    """
    if not PSUTIL_AVAILABLE:
        return {
            "available": False,
            "error": "psutil not installed",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    try:
        # Basic system info
        cpu_count_logical = psutil.cpu_count(logical=True)
        cpu_count_physical = psutil.cpu_count(logical=False)
        
        # CPU metrics (use interval=None for non-blocking measurement based on previous call)
        cpu_percent = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_freq = psutil.cpu_freq()
        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
        
        # Memory metrics
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Network metrics
        net_io = psutil.net_io_counters()
        
        # Process metrics - get current process and its children
        current_process = psutil.Process()
        try:
            children = current_process.children(recursive=True)
            process_count = 1 + len(children)
            
            # Sum up resources for main process and children (use interval=None)
            total_process_cpu = current_process.cpu_percent(interval=None)
            total_process_mem = current_process.memory_info().rss
            total_process_threads = current_process.num_threads()
            
            for child in children:
                try:
                    total_process_cpu += child.cpu_percent(interval=None)
                    total_process_mem += child.memory_info().rss
                    total_process_threads += child.num_threads()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_count = 1
            total_process_cpu = current_process.cpu_percent(interval=None)
            total_process_mem = current_process.memory_info().rss
            total_process_threads = current_process.num_threads()
        
        return {
            "available": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu": {
                "percent": round(cpu_percent, 2),
                "per_core": [round(p, 2) for p in cpu_per_core],
                "count_logical": cpu_count_logical,
                "count_physical": cpu_count_physical,
                "frequency_mhz": round(cpu_freq.current, 2) if cpu_freq else None,
                "load_avg_1m": round(load_avg[0], 2),
                "load_avg_5m": round(load_avg[1], 2),
                "load_avg_15m": round(load_avg[2], 2),
            },
            "memory": {
                "total_bytes": mem.total,
                "available_bytes": mem.available,
                "used_bytes": mem.used,
                "percent": round(mem.percent, 2),
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
            },
            "swap": {
                "total_bytes": swap.total,
                "used_bytes": swap.used,
                "free_bytes": swap.free,
                "percent": round(swap.percent, 2),
                "total_gb": round(swap.total / (1024**3), 2),
                "used_gb": round(swap.used / (1024**3), 2),
            },
            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "percent": round(disk.percent, 2),
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "read_bytes": disk_io.read_bytes if disk_io else 0,
                "write_bytes": disk_io.write_bytes if disk_io else 0,
                "read_count": disk_io.read_count if disk_io else 0,
                "write_count": disk_io.write_count if disk_io else 0,
            },
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "errin": net_io.errin,
                "errout": net_io.errout,
                "dropin": net_io.dropin,
                "dropout": net_io.dropout,
            },
            "process": {
                "count": process_count,
                "cpu_percent": round(total_process_cpu, 2),
                "memory_bytes": total_process_mem,
                "memory_mb": round(total_process_mem / (1024**2), 2),
                "threads": total_process_threads,
                "pid": current_process.pid,
            }
        }
    except Exception as exc:
        log(f"Error collecting system resources: {exc}")
        return {
            "available": False,
            "error": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def check_resource_thresholds(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check if resource usage exceeds safe thresholds and return warnings.
    """
    warnings = []
    
    if not metrics.get("available"):
        return warnings
    
    # CPU thresholds
    cpu_percent = metrics.get("cpu", {}).get("percent", 0)
    if cpu_percent > 90:
        warnings.append({
            "severity": "critical",
            "resource": "cpu",
            "message": f"CPU usage critically high at {cpu_percent}%",
            "value": cpu_percent,
            "threshold": 90
        })
    elif cpu_percent > 75:
        warnings.append({
            "severity": "warning",
            "resource": "cpu",
            "message": f"CPU usage high at {cpu_percent}%",
            "value": cpu_percent,
            "threshold": 75
        })
    
    # Memory thresholds
    mem_percent = metrics.get("memory", {}).get("percent", 0)
    if mem_percent > 90:
        warnings.append({
            "severity": "critical",
            "resource": "memory",
            "message": f"Memory usage critically high at {mem_percent}%",
            "value": mem_percent,
            "threshold": 90
        })
    elif mem_percent > 80:
        warnings.append({
            "severity": "warning",
            "resource": "memory",
            "message": f"Memory usage high at {mem_percent}%",
            "value": mem_percent,
            "threshold": 80
        })
    
    # Disk thresholds
    disk_percent = metrics.get("disk", {}).get("percent", 0)
    if disk_percent > 95:
        warnings.append({
            "severity": "critical",
            "resource": "disk",
            "message": f"Disk usage critically high at {disk_percent}%",
            "value": disk_percent,
            "threshold": 95
        })
    elif disk_percent > 85:
        warnings.append({
            "severity": "warning",
            "resource": "disk",
            "message": f"Disk usage high at {disk_percent}%",
            "value": disk_percent,
            "threshold": 85
        })
    
    # Swap usage warning
    swap_percent = metrics.get("swap", {}).get("percent", 0)
    if swap_percent > 50:
        warnings.append({
            "severity": "warning",
            "resource": "swap",
            "message": f"Swap usage at {swap_percent}%, system may be under memory pressure",
            "value": swap_percent,
            "threshold": 50
        })
    
    return warnings


def save_system_resource_state() -> None:
    """Save current system resource state and history to SQLite database."""
    ensure_dirs()
    with SYSTEM_RESOURCE_LOCK:
        # Save only recent history entries to database
        history_to_save = SYSTEM_RESOURCE_HISTORY[-SYSTEM_RESOURCE_HISTORY_SIZE:]
        
        db = get_db()
        cursor = db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        # Insert new history entries
        for entry in history_to_save:
            timestamp = entry.get("timestamp", now)
            cursor.execute(
                """INSERT INTO system_resources (timestamp, data, created_at) 
                   VALUES (?, ?, ?)""",
                (timestamp, json.dumps(entry), now)
            )
        
        # Clean up old entries (keep only the most recent SYSTEM_RESOURCE_HISTORY_SIZE * 2 entries)
        cursor.execute(
            """DELETE FROM system_resources 
               WHERE id NOT IN (
                   SELECT id FROM system_resources 
                   ORDER BY timestamp DESC 
                   LIMIT ?
               )""",
            (SYSTEM_RESOURCE_HISTORY_SIZE * 2,)
        )
        
        db.commit()


def load_system_resource_state() -> Dict[str, Any]:
    """Load system resource state from SQLite database."""
    global SYSTEM_RESOURCE_HISTORY
    ensure_dirs()
    
    db = get_db()
    cursor = db.cursor()
    
    # Load recent history
    cursor.execute(
        """SELECT data FROM system_resources 
           ORDER BY timestamp DESC 
           LIMIT ?""",
        (SYSTEM_RESOURCE_HISTORY_SIZE,)
    )
    rows = cursor.fetchall()
    
    history = []
    for row in rows:
        try:
            entry = json.loads(row[0])
            history.append(entry)
        except json.JSONDecodeError:
            pass
    
    # Reverse to get chronological order
    history.reverse()
    
    with SYSTEM_RESOURCE_LOCK:
        SYSTEM_RESOURCE_STATE.clear()
        # Current state is the most recent entry if available
        if history:
            SYSTEM_RESOURCE_STATE.update(history[-1])
        SYSTEM_RESOURCE_HISTORY.clear()
        SYSTEM_RESOURCE_HISTORY.extend(history)
    
    return get_system_resource_snapshot()


def get_system_resource_snapshot() -> Dict[str, Any]:
    """Get a snapshot of current system resources and history."""
    with SYSTEM_RESOURCE_LOCK:
        return {
            "current": copy.deepcopy(SYSTEM_RESOURCE_STATE),
            "history": copy.deepcopy(SYSTEM_RESOURCE_HISTORY[-SYSTEM_RESOURCE_HISTORY_SIZE:]),
        }


def system_resource_worker_loop() -> None:
    """Background worker that continuously monitors system resources."""
    log("System resource monitoring worker started.")
    
    last_save_time = time.time()
    save_interval = 60  # Save every 60 seconds
    
    while True:
        try:
            # Collect current metrics
            metrics = collect_system_resources()
            
            # Check for threshold warnings
            warnings = check_resource_thresholds(metrics)
            metrics["warnings"] = warnings
            
            # Log critical warnings
            for warning in warnings:
                if warning["severity"] == "critical":
                    log(f"⚠️  RESOURCE WARNING: {warning['message']}")
            
            # Update state
            with SYSTEM_RESOURCE_LOCK:
                SYSTEM_RESOURCE_STATE.clear()
                SYSTEM_RESOURCE_STATE.update(metrics)
                
                # Add to history
                history_entry = {
                    "timestamp": metrics["timestamp"],
                    "cpu_percent": metrics.get("cpu", {}).get("percent", 0),
                    "memory_percent": metrics.get("memory", {}).get("percent", 0),
                    "disk_percent": metrics.get("disk", {}).get("percent", 0),
                    "process_cpu_percent": metrics.get("process", {}).get("cpu_percent", 0),
                    "process_memory_mb": metrics.get("process", {}).get("memory_mb", 0),
                    "warnings_count": len(warnings),
                }
                SYSTEM_RESOURCE_HISTORY.append(history_entry)
                
                # Trim history to max size
                if len(SYSTEM_RESOURCE_HISTORY) > SYSTEM_RESOURCE_HISTORY_SIZE:
                    SYSTEM_RESOURCE_HISTORY[:] = SYSTEM_RESOURCE_HISTORY[-SYSTEM_RESOURCE_HISTORY_SIZE:]
            
            # Save state periodically using timestamp-based approach
            current_time = time.time()
            if current_time - last_save_time >= save_interval:
                try:
                    save_system_resource_state()
                    last_save_time = current_time
                except Exception as exc:
                    log(f"Error saving system resource state: {exc}")
            
        except Exception as exc:
            log(f"Error in system resource monitoring: {exc}")
        
        time.sleep(SYSTEM_RESOURCE_POLL_INTERVAL)


def start_system_resource_worker() -> None:
    """Start the system resource monitoring worker thread."""
    global SYSTEM_RESOURCE_THREAD
    
    if not PSUTIL_AVAILABLE:
        log("System resource monitoring disabled: psutil not available")
        return
    
    with SYSTEM_RESOURCE_LOCK:
        already_running = SYSTEM_RESOURCE_THREAD and SYSTEM_RESOURCE_THREAD.is_alive()
    
    if already_running:
        return
    
    load_system_resource_state()
    thread = threading.Thread(target=system_resource_worker_loop, name="resource-monitor", daemon=True)
    thread.start()
    
    with SYSTEM_RESOURCE_LOCK:
        SYSTEM_RESOURCE_THREAD = thread
    
    log("System resource monitoring worker initialized.")


# ================== DYNAMIC MODE MANAGEMENT ==================


def calculate_optimal_jobs() -> int:
    """
    Calculate the optimal number of concurrent jobs based on system resources.
    Returns the recommended number of jobs to run.
    """
    if not PSUTIL_AVAILABLE:
        return DYNAMIC_MODE_BASE_JOBS
    
    try:
        metrics = collect_system_resources()
        if not metrics.get("available"):
            return DYNAMIC_MODE_BASE_JOBS
        
        cpu_percent = metrics.get("cpu", {}).get("percent", 0)
        memory_percent = metrics.get("memory", {}).get("percent", 0)
        load_avg_1m = metrics.get("cpu", {}).get("load_avg_1m", 0)
        cpu_count = metrics.get("cpu", {}).get("count_logical", 1)
        
        # Start with max jobs
        recommended_jobs = DYNAMIC_MODE_MAX_JOBS
        
        # Reduce if CPU is high
        if cpu_percent > DYNAMIC_MODE_CPU_THRESHOLD:
            # Scale down based on how much we're over threshold
            # Avoid division by zero when threshold is 100%
            denominator = max(1.0, 100 - DYNAMIC_MODE_CPU_THRESHOLD)
            overage = (cpu_percent - DYNAMIC_MODE_CPU_THRESHOLD) / denominator
            reduction = int((DYNAMIC_MODE_MAX_JOBS - DYNAMIC_MODE_BASE_JOBS) * overage)
            recommended_jobs = max(DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS - reduction)
        
        # Reduce if memory is high
        if memory_percent > DYNAMIC_MODE_MEMORY_THRESHOLD:
            # Avoid division by zero when threshold is 100%
            denominator = max(1.0, 100 - DYNAMIC_MODE_MEMORY_THRESHOLD)
            overage = (memory_percent - DYNAMIC_MODE_MEMORY_THRESHOLD) / denominator
            reduction = int((DYNAMIC_MODE_MAX_JOBS - DYNAMIC_MODE_BASE_JOBS) * overage)
            recommended_jobs = min(recommended_jobs, max(DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS - reduction))
        
        # Reduce if load average is high (more than 1.5x CPU count)
        if load_avg_1m > cpu_count * 1.5:
            overage = (load_avg_1m - cpu_count * 1.5) / (cpu_count * 1.5)
            reduction = int((DYNAMIC_MODE_MAX_JOBS - DYNAMIC_MODE_BASE_JOBS) * min(overage, 1.0))
            recommended_jobs = min(recommended_jobs, max(DYNAMIC_MODE_BASE_JOBS, DYNAMIC_MODE_MAX_JOBS - reduction))
        
        return max(DYNAMIC_MODE_BASE_JOBS, min(DYNAMIC_MODE_MAX_JOBS, recommended_jobs))
    except Exception as exc:
        log(f"Error calculating optimal jobs: {exc}")
        return DYNAMIC_MODE_BASE_JOBS


def dynamic_mode_worker_loop() -> None:
    """Background worker that continuously adjusts MAX_RUNNING_JOBS based on system resources."""
    global MAX_RUNNING_JOBS
    
    log("Dynamic mode worker started.")
    last_jobs = MAX_RUNNING_JOBS
    
    while True:
        try:
            if not DYNAMIC_MODE_ENABLED:
                time.sleep(DYNAMIC_MODE_POLL_INTERVAL)
                continue
            
            # Calculate optimal job count
            optimal_jobs = calculate_optimal_jobs()
            
            # Only update if changed
            if optimal_jobs != last_jobs:
                with DYNAMIC_MODE_LOCK:
                    old_value = MAX_RUNNING_JOBS
                    MAX_RUNNING_JOBS = optimal_jobs
                    last_jobs = optimal_jobs
                
                log(f"🔄 Dynamic mode adjusted: {old_value} → {optimal_jobs} concurrent jobs")
                
                # Trigger job scheduling to take advantage of new capacity
                schedule_jobs()
        except Exception as exc:
            log(f"Error in dynamic mode worker: {exc}")
        
        time.sleep(DYNAMIC_MODE_POLL_INTERVAL)
