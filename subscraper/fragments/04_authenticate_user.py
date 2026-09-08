"""Fragment 04_authenticate_user.py. Loaded into the main module namespace."""
def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user and return user info if successful."""
    if not username or not password:
        return None
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
        (username.lower(),)
    )
    row = cursor.fetchone()
    
    if not row:
        return None
    
    if verify_password(password, row[2]):
        return {
            "id": row[0],
            "username": row[1],
            "is_admin": bool(row[3])
        }
    
    return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Get user information by ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, username, is_admin, created_at FROM users WHERE id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "is_admin": bool(row[2]),
            "created_at": row[3]
        }
    return None


def list_users() -> List[Dict[str, Any]]:
    """List all users."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at")
    rows = cursor.fetchall()
    
    return [
        {
            "id": row[0],
            "username": row[1],
            "is_admin": bool(row[2]),
            "created_at": row[3]
        }
        for row in rows
    ]


def has_admin_user() -> bool:
    """Check if at least one admin user exists."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    count = cursor.fetchone()[0]
    return count > 0


def update_user(user_id: int, username: Optional[str] = None, password: Optional[str] = None, is_admin: Optional[bool] = None) -> Tuple[bool, str]:
    """Update an existing user."""
    db = get_db()
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return False, "User not found"
    
    old_username = row[1]
    old_is_admin = bool(row[2])
    
    # Validate inputs if provided
    if username is not None:
        username = username.strip()
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
    
    if password is not None:
        password = password.strip()
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
    
    # Check if this is the last admin and trying to remove admin privileges
    if is_admin is not None and old_is_admin and not is_admin:
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        admin_count = cursor.fetchone()[0]
        if admin_count <= 1:
            return False, "Cannot remove admin privileges from the last admin user"
    
    now = datetime.now(timezone.utc).isoformat()
    
    try:
        # Build update query dynamically based on what's being updated
        updates = []
        params = []
        
        if username is not None:
            updates.append("username = ?")
            params.append(username.lower())
        
        if password is not None:
            updates.append("password_hash = ?")
            params.append(hash_password(password))
        
        if is_admin is not None:
            updates.append("is_admin = ?")
            params.append(1 if is_admin else 0)
        
        if not updates:
            return False, "No changes specified"
        
        updates.append("updated_at = ?")
        params.append(now)
        params.append(user_id)
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        db.commit()
        
        log(f"User '{old_username}' (ID: {user_id}) updated successfully")
        return True, "User updated successfully"
    except sqlite3.IntegrityError:
        return False, f"Username '{username}' already exists"
    except Exception as e:
        log(f"Error updating user: {e}")
        return False, f"Error updating user: {str(e)}"


def delete_user(user_id: int) -> Tuple[bool, str]:
    """Delete a user."""
    db = get_db()
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return False, "User not found"
    
    username = row[0]
    is_admin = bool(row[1])
    
    # Prevent deletion of the last admin
    if is_admin:
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        admin_count = cursor.fetchone()[0]
        if admin_count <= 1:
            return False, "Cannot delete the last admin user"
    
    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        log(f"User '{username}' (ID: {user_id}) deleted successfully")
        return True, f"User '{username}' deleted successfully"
    except Exception as e:
        log(f"Error deleting user: {e}")
        return False, f"Error deleting user: {str(e)}"


def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(32)


def create_session(user: Dict[str, Any]) -> str:
    """Create a new session for a user."""
    token = generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_TIMEOUT_HOURS)
    
    with SESSION_LOCK:
        SESSIONS[token] = {
            "user_id": user["id"],
            "username": user["username"],
            "is_admin": user["is_admin"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat()
        }
    
    log(f"Session created for user '{user['username']}' (expires: {expires_at.isoformat()})")
    return token


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    """Validate a session token and return user info if valid."""
    if not token:
        return None
    
    with SESSION_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        
        # Check if expired
        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.now(timezone.utc) >= expires_at:
            del SESSIONS[token]
            return None
        
        return {
            "user_id": session["user_id"],
            "username": session["username"],
            "is_admin": session["is_admin"]
        }


def delete_session(token: str) -> None:
    """Delete a session (logout)."""
    with SESSION_LOCK:
        if token in SESSIONS:
            username = SESSIONS[token].get("username", "unknown")
            del SESSIONS[token]
            log(f"Session deleted for user '{username}'")


def cleanup_expired_sessions() -> None:
    """Remove expired sessions."""
    with SESSION_LOCK:
        now = datetime.now(timezone.utc)
        expired_tokens = []
        
        for token, session in SESSIONS.items():
            expires_at = datetime.fromisoformat(session["expires_at"])
            if now >= expires_at:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del SESSIONS[token]
        
        if expired_tokens:
            log(f"Cleaned up {len(expired_tokens)} expired session(s)")


# Session cleanup worker
SESSION_CLEANUP_THREAD: Optional[threading.Thread] = None
SESSION_CLEANUP_STOP = False
SESSION_CLEANUP_INTERVAL = 600  # 10 minutes


def session_cleanup_worker() -> None:
    """Background worker that periodically cleans up expired sessions."""
    global SESSION_CLEANUP_STOP
    log("Session cleanup worker started")
    
    while not SESSION_CLEANUP_STOP:
        try:
            time.sleep(SESSION_CLEANUP_INTERVAL)
            if not SESSION_CLEANUP_STOP:
                cleanup_expired_sessions()
        except Exception as e:
            log(f"Error in session cleanup worker: {e}")
            time.sleep(60)  # Sleep a bit on error


def start_session_cleanup_worker() -> None:
    """Start the session cleanup worker thread."""
    global SESSION_CLEANUP_THREAD, SESSION_CLEANUP_STOP
    
    if SESSION_CLEANUP_THREAD and SESSION_CLEANUP_THREAD.is_alive():
        return
    
    SESSION_CLEANUP_STOP = False
    SESSION_CLEANUP_THREAD = threading.Thread(
        target=session_cleanup_worker,
        name="SessionCleanup",
        daemon=True
    )
    SESSION_CLEANUP_THREAD.start()
    log("Session cleanup worker initialized")


def _normalize_tool_flag_templates(value: Any) -> Dict[str, str]:
    mapping = {name: "" for name in TEMPLATE_AWARE_TOOLS}
    if not isinstance(value, dict):
        return mapping
    for name in TEMPLATE_AWARE_TOOLS:
        if name in value:
            mapping[name] = str(value.get(name) or "").strip()
    return mapping


def get_tool_flag_template(tool: str, config: Optional[Dict[str, Any]] = None) -> str:
    cfg = config or get_config()
    templates = _normalize_tool_flag_templates(cfg.get("tool_flag_templates"))
    return templates.get(tool, "")


def render_template_args(template: str, context: Dict[str, Any], tool: str) -> List[str]:
    if not template or not str(template).strip():
        return []

    def replacer(match: re.Match) -> str:
        key = match.group(1).upper()
        return str(context.get(key, ""))

    try:
        expanded = re.sub(r"\$(\w+)\$", replacer, str(template))
    except re.error as exc:
        log(f"Regex error while parsing template for {tool}: {exc}")
        return []
    try:
        parsed = shlex.split(expanded)
    except ValueError as exc:
        log(f"Template parse error for {tool}: {exc}")
        parsed = expanded.split()
    return [arg for arg in parsed if str(arg).strip()]


def apply_template_flags(
    tool: str,
    cmd: List[str],
    context: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> List[str]:
    template = get_tool_flag_template(tool, config)
    extras = render_template_args(template, context, tool)
    if not extras:
        return cmd
    return cmd + extras


def split_into_shards(items: List[Any], shards: int) -> List[List[Any]]:
    """Split a work list into at most `shards` balanced chunks."""
    items = list(items)
    shards = max(1, min(int(shards or 1), len(items) or 1))
    if shards <= 1 or len(items) <= 1:
        return [items] if items else []
    size, remainder = divmod(len(items), shards)
    chunks: List[List[Any]] = []
    start = 0
    for index in range(shards):
        end = start + size + (1 if index < remainder else 0)
        if start >= end:
            break
        chunks.append(items[start:end])
        start = end
    return chunks


def run_tool_shards(tool: str, items: List[Any], worker, *,
                    config: Optional[Dict[str, Any]] = None,
                    job_domain: Optional[str] = None) -> List[Any]:
    """
    Run `worker(chunk)` over the item list in parallel, one gate slot per shard,
    for tools that only handle a single target per process. Results come back in
    shard order; a shard that raises is logged and contributes nothing.
    """
    chunks = split_into_shards(items, tool_worker_limit(tool, config))
    if not chunks:
        return []
    gate = TOOL_GATES.get(tool)

    def run_chunk(chunk: List[Any]) -> Any:
        if gate is not None:
            with gate:
                return worker(chunk)
        return worker(chunk)

    if len(chunks) == 1:
        return [run_chunk(chunks[0])]

    if job_domain:
        job_log_append(job_domain,
                       f"{tool}: splitting {len(items)} target(s) across {len(chunks)} worker(s).",
                       "scheduler")

    results: List[Any] = [None] * len(chunks)
    errors: List[str] = []
    lock = threading.Lock()

    def runner(index: int, chunk: List[Any]) -> None:
        try:
            value = run_chunk(chunk)
            with lock:
                results[index] = value
        except Exception as exc:
            log(f"{tool} worker {index + 1} failed: {exc}")
            with lock:
                errors.append(str(exc))

    threads = [threading.Thread(target=runner, args=(index, chunk),
                                name=f"{tool}-worker-{index + 1}", daemon=True)
               for index, chunk in enumerate(chunks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if errors and job_domain:
        job_log_append(job_domain, f"{tool}: {len(errors)} worker(s) failed: {errors[0]}", tool)
    return results
