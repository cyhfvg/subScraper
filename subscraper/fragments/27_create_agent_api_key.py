"""Fragment 27_create_agent_api_key.py. Loaded into the main module namespace."""
def create_agent_api_key(name: str, scopes: Any, programs: Optional[List[str]] = None,
                         expires_days: Optional[int] = None,
                         created_by: Optional[str] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Create a scoped API key. The plaintext key is returned exactly once; only a
    SHA-256 digest of the secret half is stored.
    """
    name = (name or "").strip()
    if not name:
        return False, "Key name is required.", None
    if len(name) > 100:
        return False, "Key name must be 100 characters or fewer.", None

    valid_scopes, unknown = normalize_agent_scopes(scopes)
    if unknown:
        return False, f"Unknown scope(s): {', '.join(unknown)}. Valid scopes: {', '.join(AGENT_API_SCOPES)}", None
    if not valid_scopes:
        return False, f"At least one scope is required. Valid scopes: {', '.join(AGENT_API_SCOPES)}", None

    program_ids: List[str] = []
    if programs:
        if isinstance(programs, str):
            programs = [programs]
        for pid in programs:
            pid = str(pid).strip()
            if not pid:
                continue
            if not get_program(pid):
                return False, f"Unknown program id: {pid}", None
            if pid not in program_ids:
                program_ids.append(pid)

    expires_at = None
    if expires_days not in (None, ""):
        try:
            days = int(expires_days)
        except (TypeError, ValueError):
            return False, "expires_days must be an integer.", None
        if days <= 0:
            return False, "expires_days must be positive.", None
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    api_key = f"{AGENT_KEY_PREFIX}_{key_id}_{secret}"
    now = _now_iso()

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        INSERT INTO agent_api_keys
            (key_id, name, key_hash, scopes, programs, created_by, created_at, expires_at, revoked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (key_id, name, _hash_api_secret(secret), json.dumps(valid_scopes),
         json.dumps(program_ids), created_by or "", now, expires_at),
    )
    db.commit()
    log(f"Created agent API key '{name}' ({key_id}) with scopes {valid_scopes}")

    return True, "API key created. Store it now - it will not be shown again.", {
        "key_id": key_id,
        "api_key": api_key,
        "name": name,
        "scopes": valid_scopes,
        "programs": program_ids,
        "created_at": now,
        "expires_at": expires_at,
    }


def _row_to_agent_key(row: Any, include_hash: bool = False) -> Dict[str, Any]:
    try:
        scopes = json.loads(row["scopes"] or "[]")
    except (json.JSONDecodeError, TypeError):
        scopes = []
    try:
        programs = json.loads(row["programs"] or "[]")
    except (json.JSONDecodeError, TypeError):
        programs = []
    data = {
        "key_id": row["key_id"],
        "name": row["name"],
        "scopes": scopes,
        "programs": programs,
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "last_used_at": row["last_used_at"],
        "revoked": bool(row["revoked"]),
    }
    if include_hash:
        data["key_hash"] = row["key_hash"]
    return data


def list_agent_api_keys() -> List[Dict[str, Any]]:
    """List API keys without any secret material."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM agent_api_keys ORDER BY created_at DESC")
    return [_row_to_agent_key(row) for row in cursor.fetchall()]


def revoke_agent_api_key(key_id: str) -> Tuple[bool, str]:
    key_id = (key_id or "").strip()
    if not key_id:
        return False, "key_id is required."
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE agent_api_keys SET revoked = 1 WHERE key_id = ?", (key_id,))
    db.commit()
    if cursor.rowcount == 0:
        return False, "API key not found."
    log(f"Revoked agent API key {key_id}")
    return True, "API key revoked."


def delete_agent_api_key(key_id: str) -> Tuple[bool, str]:
    key_id = (key_id or "").strip()
    if not key_id:
        return False, "key_id is required."
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM agent_api_keys WHERE key_id = ?", (key_id,))
    db.commit()
    if cursor.rowcount == 0:
        return False, "API key not found."
    log(f"Deleted agent API key {key_id}")
    return True, "API key deleted."


def validate_agent_api_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """Validate a presented API key. Returns the key record or None."""
    raw_key = (raw_key or "").strip()
    if not raw_key:
        return None
    parts = raw_key.split("_", 2)
    if len(parts) != 3 or parts[0] != AGENT_KEY_PREFIX:
        return None
    _, key_id, secret = parts

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM agent_api_keys WHERE key_id = ?", (key_id,))
    row = cursor.fetchone()
    if not row:
        return None
    record = _row_to_agent_key(row, include_hash=True)
    if not hmac.compare_digest(record.pop("key_hash", ""), _hash_api_secret(secret)):
        return None
    if record["revoked"]:
        return None
    if record["expires_at"]:
        try:
            if datetime.fromisoformat(record["expires_at"]) <= datetime.now(timezone.utc):
                return None
        except ValueError:
            pass

    cursor.execute("UPDATE agent_api_keys SET last_used_at = ? WHERE key_id = ?", (_now_iso(), key_id))
    db.commit()
    return record


# --- Program scope model ----------------------------------------------------

def _scope_pattern_host(entry: str) -> Optional[str]:
    """Extract a host pattern from a scope entry (bare domain, wildcard or URL)."""
    value = (entry or "").strip().lower()
    if not value:
        return None
    if "://" in value:
        try:
            parsed = urlparse(value)
        except ValueError:
            return None
        host = (parsed.netloc or "").split("@")[-1]
    else:
        host = value.split("/")[0]
    host = host.split(":")[0].strip().strip(".")
    if not host:
        return None
    # Only treat it as a host pattern if it looks like a hostname/wildcard.
    if not re.fullmatch(r"[a-z0-9\*\.\-_]+", host):
        return None
    return host


def parse_scope_entry(entry: str) -> Dict[str, Any]:
    """Normalize one scope line into {raw, host, wildcard, kind}."""
    raw = (entry or "").strip()
    host = _scope_pattern_host(raw)
    if not host:
        return {"raw": raw, "host": None, "wildcard": False, "kind": "other"}
    return {
        "raw": raw,
        "host": host,
        "wildcard": "*" in host,
        "kind": "url" if "://" in raw.lower() else "domain",
    }


def host_matches_scope_pattern(host: str, pattern: str) -> bool:
    """
    Match a hostname against a scope pattern.

    `*.example.com` matches example.com and any subdomain of it (the usual bug
    bounty reading of a wildcard root). Other `*` placements are glob-matched.
    """
    host = (host or "").strip().lower().strip(".")
    pattern = (pattern or "").strip().lower().strip(".")
    if not host or not pattern:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return bool(suffix) and (host == suffix or host.endswith("." + suffix))
    if "*" in pattern:
        regex = "^" + "".join(".*" if ch == "*" else re.escape(ch) for ch in pattern) + "$"
        return re.match(regex, host) is not None
    return False


def evaluate_asset_scope(asset: str, in_scope: List[str], out_of_scope: List[str]) -> Dict[str, Any]:
    """
    Decide whether one asset is in scope. Out-of-scope always wins so an agent
    never gets told to touch an excluded host.
    """
    raw_asset = (asset or "").strip()
    host = _scope_pattern_host(raw_asset)
    result: Dict[str, Any] = {
        "asset": raw_asset,
        "host": host,
        "in_scope": False,
        "matched": None,
        "reason": "",
    }
    if not raw_asset:
        result["reason"] = "Empty asset."
        return result

    for pattern in out_of_scope or []:
        parsed = parse_scope_entry(pattern)
        if parsed["host"] and host and host_matches_scope_pattern(host, parsed["host"]):
            result["matched"] = parsed["raw"]
            result["reason"] = f"Excluded by out-of-scope rule '{parsed['raw']}'."
            return result
        if parsed["raw"].lower() == raw_asset.lower():
            result["matched"] = parsed["raw"]
            result["reason"] = f"Excluded by out-of-scope rule '{parsed['raw']}'."
            return result

    for pattern in in_scope or []:
        parsed = parse_scope_entry(pattern)
        if parsed["host"] and host and host_matches_scope_pattern(host, parsed["host"]):
            result["in_scope"] = True
            result["matched"] = parsed["raw"]
            result["reason"] = f"Matched in-scope rule '{parsed['raw']}'."
            return result
        if parsed["raw"].lower() == raw_asset.lower():
            result["in_scope"] = True
            result["matched"] = parsed["raw"]
            result["reason"] = f"Matched in-scope rule '{parsed['raw']}'."
            return result

    result["reason"] = "No in-scope rule matched."
    return result


def program_root_targets(program: Dict[str, Any]) -> List[str]:
    """Root domains that should be enumerated for a program, out-of-scope removed."""
    scope = program.get("scope", {})
    in_scope = scope.get("in_scope", []) or []
    out_of_scope = scope.get("out_of_scope", []) or []
    roots: List[str] = []
    for entry in in_scope:
        parsed = parse_scope_entry(entry)
        host = parsed["host"]
        if not host:
            continue
        while host.startswith("*."):
            host = host[2:]
        if "*" in host:
            continue
        host = host.strip(".")
        if not host or host in roots:
            continue
        verdict = evaluate_asset_scope(host, in_scope, out_of_scope)
        if not verdict["in_scope"]:
            continue
        roots.append(host)
    return roots


# --- Program CRUD -----------------------------------------------------------

def _row_to_program(row: Any) -> Dict[str, Any]:
    try:
        data = json.loads(row["data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        data = {}
    scope = data.get("scope", {}) or {}
    return {
        "id": row["id"],
        "name": row["name"],
        "platform": row["platform"] or "",
        "handle": data.get("handle", ""),
        "url": data.get("url", ""),
        "notes": data.get("notes", ""),
        "tags": data.get("tags", []),
        "scope": {
            "in_scope": scope.get("in_scope", []),
            "out_of_scope": scope.get("out_of_scope", []),
        },
        "last_investigated_at": data.get("last_investigated_at"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _clean_scope_list(value: Any) -> List[str]:
    if isinstance(value, str):
        items = [part for part in re.split(r"[,\n\r]+", value)]
    elif isinstance(value, (list, tuple, set)):
        items = [str(part) for part in value]
    else:
        items = []
    cleaned: List[str] = []
    for item in items:
        item = item.strip()
        if not item or item in cleaned:
            continue
        cleaned.append(item)
    return cleaned[:5000]


def create_program(payload: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Create a program from a full scope definition."""
    name = str(payload.get("name") or "").strip()
    if not name:
        return False, "Program name is required.", None

    in_scope = _clean_scope_list(payload.get("in_scope") or (payload.get("scope") or {}).get("in_scope"))
    out_of_scope = _clean_scope_list(payload.get("out_of_scope") or (payload.get("scope") or {}).get("out_of_scope"))
    if not in_scope:
        return False, "At least one in-scope entry is required.", None

    program_id = str(payload.get("id") or "").strip().lower()
    if program_id and not re.fullmatch(r"[a-z0-9][a-z0-9._\-]{0,63}", program_id):
        return False, ("Program id must be 1-64 chars of letters, digits, '.', '_' or '-' "
                       "and start with a letter or digit."), None
    if not program_id:
        program_id = re.sub(r"[^a-z0-9\-]+", "-", name.lower()).strip("-")[:48]
    if not program_id:
        program_id = uuid.uuid4().hex[:12]
    if get_program(program_id):
        return False, f"Program '{program_id}' already exists. Use the update endpoint.", None

    now = _now_iso()
    data = {
        "handle": str(payload.get("handle") or "").strip(),
        "url": str(payload.get("url") or "").strip(),
        "notes": str(payload.get("notes") or "").strip(),
        "tags": _clean_scope_list(payload.get("tags")),
        "scope": {"in_scope": in_scope, "out_of_scope": out_of_scope},
    }

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO programs (id, name, platform, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (program_id, name, str(payload.get("platform") or "").strip(), json.dumps(data), now, now),
    )
    db.commit()
    log(f"Created program '{program_id}' with {len(in_scope)} in-scope and {len(out_of_scope)} out-of-scope entries")
    return True, f"Program '{program_id}' created.", get_program(program_id)


def update_program(program_id: str, payload: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Patch a program. Only provided fields change."""
    program = get_program(program_id)
    if not program:
        return False, "Program not found.", None

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT data FROM programs WHERE id = ?", (program_id,))
    row = cursor.fetchone()
    try:
        data = json.loads(row["data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        data = {}
    scope = data.setdefault("scope", {})

    name = program["name"]
    if "name" in payload:
        candidate = str(payload.get("name") or "").strip()
        if not candidate:
            return False, "Program name cannot be empty.", None
        name = candidate
    platform = str(payload.get("platform", program["platform"]) or "").strip()

    scope_payload = payload.get("scope") or {}
    if "in_scope" in payload or "in_scope" in scope_payload:
        in_scope = _clean_scope_list(payload.get("in_scope", scope_payload.get("in_scope")))
        if not in_scope:
            return False, "At least one in-scope entry is required.", None
        scope["in_scope"] = in_scope
    if "out_of_scope" in payload or "out_of_scope" in scope_payload:
        scope["out_of_scope"] = _clean_scope_list(payload.get("out_of_scope", scope_payload.get("out_of_scope")))
    for field in ("handle", "url", "notes"):
        if field in payload:
            data[field] = str(payload.get(field) or "").strip()
    if "tags" in payload:
        data["tags"] = _clean_scope_list(payload.get("tags"))

    cursor.execute(
        "UPDATE programs SET name = ?, platform = ?, data = ?, updated_at = ? WHERE id = ?",
        (name, platform, json.dumps(data), _now_iso(), program_id),
    )
    db.commit()
    return True, f"Program '{program_id}' updated.", get_program(program_id)


def get_program(program_id: str) -> Optional[Dict[str, Any]]:
    program_id = (program_id or "").strip()
    if not program_id:
        return None
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM programs WHERE id = ?", (program_id,))
    row = cursor.fetchone()
    return _row_to_program(row) if row else None


def list_programs() -> List[Dict[str, Any]]:
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM programs ORDER BY updated_at DESC")
    return [_row_to_program(row) for row in cursor.fetchall()]


def delete_program(program_id: str) -> Tuple[bool, str]:
    program_id = (program_id or "").strip()
    if not program_id:
        return False, "Program id is required."
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM programs WHERE id = ?", (program_id,))
    db.commit()
    if cursor.rowcount == 0:
        return False, "Program not found."
    return True, f"Program '{program_id}' deleted. Recon data for its domains was kept."
