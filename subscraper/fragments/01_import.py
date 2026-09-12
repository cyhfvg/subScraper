"""Fragment 01_import.py. Loaded into the main module namespace."""
import argparse
import logging
import copy
import csv
import hashlib
import hmac
import io
import json
import mimetypes
import os
import platform
import re
import secrets
import shlex
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse, unquote, urljoin
from urllib.request import Request, urlopen

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. System resource monitoring will be disabled.")

# ====================== CONFIG ======================

DATA_DIR = Path("recon_data")
DB_FILE = DATA_DIR / "recon.db"
STATE_FILE = DATA_DIR / "state.json"
HTML_DASHBOARD_FILE = DATA_DIR / "dashboard.html"
LOCK_FILE = DATA_DIR / ".lock"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_DIR = DATA_DIR / "history"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
MONITORS_FILE = DATA_DIR / "monitors.json"
BACKUPS_DIR = DATA_DIR / "backups"
COMPLETED_JOBS_FILE = DATA_DIR / "completed_jobs.json"
ACTIVE_JOBS_FILE = DATA_DIR / "active_jobs.json"
WORDLISTS_DIR = DATA_DIR / "wordlists"
RESOLVERS_FILE = DATA_DIR / "resolvers.txt"

# Nuclei templates shipped with this repo: CVEs that have no template in the
# official projectdiscovery/nuclei-templates repo. Run alongside the defaults.
BUNDLED_NUCLEI_TEMPLATES_DIR = Path(__file__).resolve().parent / "nuclei-templates"

# Authentication & Session Management
SESSION_TIMEOUT_HOURS = 24
SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_LOCK = threading.Lock()

# SQLite connection pool
DB_LOCK = threading.Lock()
DB_CONN: Optional[sqlite3.Connection] = None

DEFAULT_INTERVAL = 30
HTML_REFRESH_SECONDS = DEFAULT_INTERVAL  # default; can be overridden
MAX_JOB_LOG_LINES = 400
MAX_JOB_LOG_LINE_LENGTH = 500


# Severity levels for security findings
SEVERITY_LEVELS = ['NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

# Tool names (can be adjusted per OS if needed)
TOOLS = {
    "dnsx": "dnsx",
    "nmap": "nmap",
    "ffuf": "ffuf",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "nikto": "nikto",
    "gowitness": "gowitness",
}

CONFIG_LOCK = threading.Lock()
CONFIG: Dict[str, Any] = {}
TEMPLATE_AWARE_TOOLS = [
    "dnsx",
    "nmap",
    "ffuf",
    "httpx",
    "nuclei",
    "nikto",
    "gowitness",
]


class ToolGate:
    """
    Concurrency gate for tools with backlog queue support.
    
    When the tool is at capacity, work items are queued and processed
    when capacity becomes available. This prevents jobs from blocking
    indefinitely and allows them to proceed with other tools.
    """
    def __init__(self, limit: int):
        self._limit = max(1, int(limit))
        self._count = 0
        self._cond = threading.Condition()
        self._queue: deque = deque()  # Backlog queue for pending work
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_worker = False
        self._start_worker()
    
    def _start_worker(self) -> None:
        """Start background worker thread to process queued work."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._stop_worker = False
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name=f"ToolGate-Worker",
                daemon=True
            )
            self._worker_thread.start()
    
    def _worker_loop(self) -> None:
        """Background worker that processes queued work items."""
        while not self._stop_worker:
            work_item = None
            with self._cond:
                # Wait for work or until stopped
                while not self._queue and not self._stop_worker:
                    self._cond.wait(timeout=1.0)
                
                if self._stop_worker:
                    break
                
                # Wait for available capacity
                while self._count >= self._limit and not self._stop_worker:
                    self._cond.wait(timeout=1.0)
                
                if self._stop_worker:
                    break
                
                # Get work from queue if available
                if self._queue:
                    work_item = self._queue.popleft()
                    self._count += 1
            
            # Run the item on its own thread so a limit of N really means N
            # items in flight. Executing it here would serialise the queue no
            # matter how high the limit was set.
            if work_item:
                threading.Thread(target=self._execute, args=(work_item,),
                                 name="ToolGate-Task", daemon=True).start()

    def _execute(self, work_item) -> None:
        """Run one queued work item and release its slot afterwards."""
        func, result_callback, error_callback = work_item
        try:
            result = func()
            if result_callback:
                result_callback(result)
        except Exception as exc:
            if error_callback:
                error_callback(exc)
        finally:
            with self._cond:
                if self._count > 0:
                    self._count -= 1
                self._cond.notify_all()
    
    def stop_worker(self) -> None:
        """Stop the background worker thread."""
        with self._cond:
            self._stop_worker = True
            self._cond.notify_all()
    
    def enqueue(self, func, result_callback=None, error_callback=None) -> None:
        """
        Enqueue a work item to be executed when capacity is available.
        
        Args:
            func: Callable to execute (no arguments)
            result_callback: Optional callback for successful result
            error_callback: Optional callback for exceptions
        """
        with self._cond:
            self._queue.append((func, result_callback, error_callback))
            self._cond.notify_all()
    
    def acquire(self) -> None:
        """Acquire a slot (blocking). For backward compatibility."""
        with self._cond:
            while self._count >= self._limit:
                self._cond.wait()
            self._count += 1

    def release(self) -> None:
        """Release a slot. For backward compatibility."""
        with self._cond:
            if self._count > 0:
                self._count -= 1
            self._cond.notify_all()

    def update_limit(self, limit: int) -> None:
        """Update the concurrency limit."""
        with self._cond:
            self._limit = max(1, int(limit))
            self._cond.notify_all()

    def snapshot(self) -> Dict[str, int]:
        """Get current status snapshot."""
        with self._cond:
            return {
                "limit": self._limit,
                "active": self._count,
                "queued": len(self._queue),
            }

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()


# How many concurrent workers each tool gets when its own max_parallel_* is
# left at 0. Five keeps a normal laptop busy without drowning it; the System
# Resources view and dynamic mode are there to catch the cases where it does.
DEFAULT_TOOL_WORKERS = 5
MAX_TOOL_WORKERS = 50

# Steps whose host list is split across several parallel tool processes. These
# tools take a batch of hosts per run, so N workers means N processes each
# handling a slice of the batch.
SHARDED_TOOLS = {"httpx", "nuclei", "nikto"}

TOOL_PARALLEL_FIELDS = {
    "dnsx": "max_parallel_dnsx",
    "nmap": "max_parallel_nmap",
    "ffuf": "max_parallel_ffuf",
    "httpx": "max_parallel_httpx",
    "gowitness": "max_parallel_gowitness",
    "nuclei": "max_parallel_nuclei",
    "nikto": "max_parallel_nikto",
}


def default_tool_workers(config: Optional[Dict[str, Any]] = None) -> int:
    """Worker count applied to any tool that has no explicit override."""
    cfg = config if config is not None else get_config()
    try:
        value = int(cfg.get("default_tool_workers", DEFAULT_TOOL_WORKERS) or DEFAULT_TOOL_WORKERS)
    except (TypeError, ValueError):
        value = DEFAULT_TOOL_WORKERS
    return max(1, min(MAX_TOOL_WORKERS, value))


def tool_worker_limit(tool: str, config: Optional[Dict[str, Any]] = None) -> int:
    """
    Workers for one tool: its own max_parallel_* when set, otherwise the global
    default. 0 or blank means "inherit", which is what makes one setting enough
    to scale every tool.
    """
    cfg = config if config is not None else get_config()
    field = TOOL_PARALLEL_FIELDS.get(tool)
    raw = cfg.get(field) if field else None
    if raw in (None, "", 0, "0"):
        return default_tool_workers(cfg)
    try:
        return max(1, min(MAX_TOOL_WORKERS, int(raw)))
    except (TypeError, ValueError):
        return default_tool_workers(cfg)


TOOL_GATES: Dict[str, ToolGate] = {
    "dnsx": ToolGate(DEFAULT_TOOL_WORKERS),
    "nmap": ToolGate(DEFAULT_TOOL_WORKERS),
    "ffuf": ToolGate(DEFAULT_TOOL_WORKERS),
    "httpx": ToolGate(DEFAULT_TOOL_WORKERS),
    "gowitness": ToolGate(DEFAULT_TOOL_WORKERS),
    "nuclei": ToolGate(DEFAULT_TOOL_WORKERS),
    "nikto": ToolGate(DEFAULT_TOOL_WORKERS),
}

# State payload cache for improved performance
STATE_CACHE_LOCK = threading.Lock()
STATE_CACHE: Dict[str, Any] = {
    "etag": None,
    "payload": None,
    "last_updated": None,
}

JOB_QUEUE: deque = deque()
MAX_RUNNING_JOBS = 1
RUNNING_JOBS: Dict[str, Dict[str, Any]] = {}
COMPLETED_JOBS: Dict[str, Dict[str, Any]] = {}  # Store completed job reports
MAX_COMPLETED_JOBS_PER_DOMAIN = 10  # Keep last N completed jobs per domain
JOB_LOCK = threading.Lock()
PIPELINE_STEPS = ["dnsx", "port_scan", "httpx", "vhost_enum", "screenshots", "nuclei", "jsscan", "nikto"]

# Global rate limiter
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_LAST_CALL = 0.0
GLOBAL_RATE_LIMIT_DELAY = 0.0  # seconds between tool calls (0 = no rate limit)

# Timeout tracking for intelligent rate limit adjustment
TIMEOUT_TRACKER_LOCK = threading.Lock()
TIMEOUT_TRACKER: Dict[str, Dict[str, Any]] = {}  # domain -> {errors: int, last_error_time: float, backoff_delay: float}
TIMEOUT_ERROR_THRESHOLD = 3  # Number of errors before increasing rate limit
TIMEOUT_BACKOFF_INCREMENT = 5.0  # Seconds to add to delay after threshold (increased from 2.0 to back off more aggressively)
MAX_AUTO_BACKOFF_DELAY = 30.0  # Maximum automatic backoff delay

STEP_PROGRESS = {
    "pending": 0,
    "queued": 0,
    "running": 55,
    "completed": 100,
    "skipped": 0,
    "error": 100,
    "failed": 100,
}

# Dynamic queue management
DYNAMIC_MODE_ENABLED = False
DYNAMIC_MODE_LOCK = threading.Lock()
DYNAMIC_MODE_THREAD: Optional[threading.Thread] = None
DYNAMIC_MODE_POLL_INTERVAL = 30  # Check every 30 seconds
DYNAMIC_MODE_BASE_JOBS = 1  # Minimum jobs when dynamic mode is enabled
DYNAMIC_MODE_MAX_JOBS = 10  # Maximum jobs when dynamic mode is enabled
DYNAMIC_MODE_CPU_THRESHOLD = 75.0  # CPU % threshold
DYNAMIC_MODE_MEMORY_THRESHOLD = 80.0  # Memory % threshold

# Auto-backup system
AUTO_BACKUP_ENABLED = False
AUTO_BACKUP_LOCK = threading.Lock()
AUTO_BACKUP_THREAD: Optional[threading.Thread] = None
AUTO_BACKUP_INTERVAL = 3600  # Default: 1 hour in seconds
AUTO_BACKUP_MAX_COUNT = 10  # Keep last 10 backups
LAST_BACKUP_TIME = 0.0


class JobCancelled(Exception):
    """流水线在检查点发现用户删除/取消请求时抛出.

    Args:
        domain: 被取消的任务域名.
    """

    def __init__(self, domain: str = "") -> None:
        self.domain = domain
        super().__init__(f"Job cancelled: {domain}")


class JobControl:
    """单 Job 的暂停/恢复/取消控制器.

    Example:
        ctrl = JobControl()
        ctrl.request_pause()
        ctrl.request_cancel()
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._pause_requested = False
        self._cancel_requested = False

    def request_pause(self) -> bool:
        """请求暂停.

        Returns:
            True 表示新的暂停请求已生效, False 表示已经处于暂停.
        Raises:
            无.
        """
        with self._cond:
            if self._cancel_requested:
                return False
            if self._pause_requested:
                return False
            self._pause_requested = True
            self._cond.notify_all()
            return True

    def request_resume(self) -> bool:
        """请求恢复.

        Returns:
            True 表示从暂停恢复, False 表示当前未暂停.
        Raises:
            无.
        """
        with self._cond:
            if not self._pause_requested:
                return False
            self._pause_requested = False
            self._cond.notify_all()
            return True

    def request_cancel(self) -> bool:
        """请求取消/删除正在运行的 Job, 并唤醒暂停等待.

        Returns:
            True 表示新的取消请求已生效, False 表示已经在取消.
        Raises:
            无.
        Example:
            ctrl.request_cancel()
        """
        with self._cond:
            if self._cancel_requested:
                return False
            self._cancel_requested = True
            self._pause_requested = False
            self._cond.notify_all()
            return True

    def is_pause_requested(self) -> bool:
        """是否处于暂停请求中.

        Returns:
            暂停标志.
        Raises:
            无.
        """
        with self._cond:
            return self._pause_requested

    def is_cancel_requested(self) -> bool:
        """是否处于取消请求中.

        Returns:
            取消标志.
        Raises:
            无.
        """
        with self._cond:
            return self._cancel_requested

    def wait_until_resumed(self) -> None:
        """阻塞直到恢复或取消.

        Returns:
            None.
        Raises:
            无. 取消由调用方在返回后检查 is_cancel_requested.
        """
        with self._cond:
            while self._pause_requested and not self._cancel_requested:
                self._cond.wait()


def is_rate_limit_error(error: Exception) -> bool:
    """
    Check if an error indicates rate limiting or too many requests.
    """
    error_str = str(error).lower()
    error_type = type(error).__name__.lower()
    
    # Check for HTTP 429 (Too Many Requests) or 503 (Service Unavailable)
    if isinstance(error, HTTPError):
        if error.code in (429, 503):
            return True
    
    # Check for timeout errors
    if "timeout" in error_str or "timed out" in error_str:
        return True
    
    # Check for connection errors that might indicate rate limiting
    if "connection" in error_str and ("refused" in error_str or "reset" in error_str):
        return True
    
    # Check for rate limit keywords in error message
    rate_limit_keywords = ["rate limit", "too many requests", "throttle", "slow down"]
    if any(keyword in error_str for keyword in rate_limit_keywords):
        return True
    
    return False
