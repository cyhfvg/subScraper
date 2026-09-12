"""HTTP handler mixin: HandlerGetMixin."""
class HandlerGetMixin:
    def do_GET(self):
        route = urlparse(self.path).path or "/"
        # Public endpoints (no auth required)
        if route == "/login":
            self._send_login_page()
            return

        if route.startswith("/static/"):
            if serve_static_asset(self):
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        
        # Bug bounty agent API - authenticates via scoped API key or session
        if route == "/api/agent" or route.startswith("/api/agent/"):
            self._handle_agent_get()
            return

        # All other endpoints require authentication
        user = self._require_auth()
        if not user:
            return
        
        if route in ("/", "/index.html"):
            self._send_bytes(INDEX_HTML.encode("utf-8"))
            return
        
        # Domain detail page route
        if self.path.startswith("/domain/"):
            domain = unquote(self.path[len("/domain/"):]).strip().lower()
            if domain:
                self._send_bytes(generate_domain_detail_page(domain).encode("utf-8"))
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        
        # Subdomain detail page route
        if self.path.startswith("/subdomain/"):
            parts = self.path[len("/subdomain/"):].split("/", 1)
            if len(parts) == 2:
                domain = unquote(parts[0]).strip().lower()
                subdomain = unquote(parts[1]).strip().lower()
                self._send_bytes(generate_subdomain_detail_page(domain, subdomain).encode("utf-8"))
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        
        # Screenshots gallery page route
        if self.path.startswith("/gallery/"):
            domain = unquote(self.path[len("/gallery/"):]).strip().lower()
            if domain:
                self._send_bytes(generate_screenshots_gallery_page(domain).encode("utf-8"))
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        
        # API endpoint for domain detail data
        if self.path.startswith("/api/domain/"):
            domain = unquote(self.path[len("/api/domain/"):]).strip().lower()
            if domain:
                state = load_state()
                target = state.get("targets", {}).get(domain)
                if not target:
                    self._send_json({"success": False, "message": "Domain not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                self._send_json({
                    "success": True,
                    "domain": domain,
                    "data": target
                })
                return
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid request")
            return
        
        # API endpoint for subdomain detail data
        if self.path.startswith("/api/subdomain/"):
            parts = self.path[len("/api/subdomain/"):].split("/", 1)
            if len(parts) == 2:
                domain = unquote(parts[0]).strip().lower()
                subdomain = unquote(parts[1]).strip().lower()
                state = load_state()
                target = state.get("targets", {}).get(domain)
                if not target or not target.get("subdomains", {}).get(subdomain):
                    self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                sub_data = target["subdomains"][subdomain]
                # Include domain-level endpoints that might be relevant to this subdomain
                domain_endpoints = target.get("endpoints", [])
                # Filter endpoints that contain this subdomain
                relevant_endpoints = [url for url in domain_endpoints if subdomain in url]
                try:
                    # OPTIMIZATION: Load only recent history for subdomain detail page (limit for performance)
                    # Reduced to 500 entries for better performance with large datasets
                    history = load_domain_history(domain, limit=500)
                except Exception:
                    history = []
                self._send_json({
                    "success": True,
                    "domain": domain,
                    "subdomain": subdomain,
                    "data": sub_data,
                    "endpoints": relevant_endpoints,
                    "flags": target.get("flags", {}),
                    "history": history
                })
                return
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid request")
            return
        
        # API endpoint for screenshots gallery data
        if self.path.startswith("/api/gallery/"):
            domain = unquote(self.path[len("/api/gallery/"):]).strip().lower()
            if domain:
                state = load_state()
                target = state.get("targets", {}).get(domain)
                if not target:
                    self._send_json({"success": False, "message": "Domain not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                # Self-heal: attach any on-disk screenshots missing from state.
                try:
                    if reconcile_screenshots_from_disk(state, domain) > 0:
                        save_state(state)
                        target = state.get("targets", {}).get(domain, target)
                except Exception as exc:
                    log(f"Screenshot reconcile failed for {domain}: {exc}")
                screenshots = []
                subdomains = target.get("subdomains", {})
                for sub, data in subdomains.items():
                    screenshot = data.get("screenshot")
                    if screenshot and screenshot.get("path"):
                        httpx = data.get("httpx") or {}
                        screenshots.append({
                            "subdomain": sub,
                            "path": screenshot["path"],
                            "url": httpx.get("url", f"http://{sub}"),
                            "title": httpx.get("title", ""),
                            "status_code": httpx.get("status_code"),
                            "captured_at": screenshot.get("captured_at"),
                        })
                screenshots.sort(key=lambda x: x.get("captured_at") or "", reverse=True)
                self._send_json({
                    "success": True,
                    "domain": domain,
                    "screenshots": screenshots
                })
                return
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid request")
            return
        
        if self.path.startswith("/api/state"):
            # Parse query parameters
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            full = params.get("full", ["false"])[0].lower() in ("true", "1", "yes")
            
            # OPTIMIZATION: Pagination support for large datasets
            page = 1
            per_page = None  # None = no pagination (default for backward compatibility)
            if "page" in params:
                try:
                    page = max(1, int(params["page"][0]))
                except (ValueError, IndexError):
                    page = 1
            if "per_page" in params:
                try:
                    per_page = max(1, min(1000, int(params["per_page"][0])))  # Max 1000 per page
                except (ValueError, IndexError):
                    per_page = None
            
            # Get cached payload with ETag (pagination not cached - would explode cache)
            if per_page is None:
                etag, payload = get_cached_state_payload(full=full)
                
                # Check If-None-Match header for conditional requests
                client_etag = self.headers.get("If-None-Match")
                if client_etag and client_etag == etag:
                    # Client has current version - return 304 Not Modified
                    self.send_response(HTTPStatus.NOT_MODIFIED)
                    self.send_header("ETag", etag)
                    self.end_headers()
                    return
            else:
                # Paginated requests bypass cache
                if full:
                    payload = build_state_payload_paginated(page=page, per_page=per_page, full=True)
                else:
                    payload = build_state_payload_paginated(page=page, per_page=per_page, full=False)
                etag = None
            
            # Return payload with ETag header (if not paginated)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if etag:
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "must-revalidate")  # Require validation with origin
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/api/settings":
            self._send_json({"config": get_config()})
            return
        if self.path == "/api/workers":
            # OPTIMIZATION: Workers endpoint for real-time updates (never cached)
            # Workers dashboard needs live data, not cached state
            self._send_json({"workers": snapshot_workers()})
            return
        if self.path == "/api/api-keys":
            self._send_json({"success": False, "message": "Internet API keys are not used in intranet mode."}, status=HTTPStatus.GONE)
            return
        if self.path == "/api/monitors":
            self._send_json({"monitors": list_monitors()})
            return
        if self.path == "/api/system-resources":
            self._send_json(get_system_resource_snapshot())
            return
        if self.path.startswith("/api/tools"):
            params = parse_qs(urlparse(self.path).query)
            refresh = params.get("refresh", ["false"])[0].lower() in ("true", "1", "yes")
            if refresh:
                detect_platform(refresh=True)
                _PKG_AVAILABILITY_CACHE.clear()
                invalidate_tool_path_cache()
            self._send_json({"success": True, **tool_status_snapshot()})
            return
        if self.path.startswith("/api/js-findings"):
            params = parse_qs(urlparse(self.path).query)
            try:
                limit = max(1, min(200, int(params.get("limit", ["10"])[0])))
            except (TypeError, ValueError):
                limit = 10
            self._send_json({"success": True,
                             **js_findings_overview(limit_targets=limit, limit_secrets=limit)})
            return
        if self.path == "/api/dynamic-mode":
            self._send_json(get_dynamic_mode_status())
            return
        if self.path == "/api/auto-backup-status":
            self._send_json(get_auto_backup_status())
            return
        if self.path == "/api/cleanup-status":
            self._send_json(get_cleanup_status())
            return
        if self.path == "/api/auth/user":
            # Return current user info
            self._send_json({"success": True, "user": {"username": user["username"], "is_admin": user["is_admin"]}})
            return
        if self.path == "/api/users":
            # List users (admin only)
            if not user.get("is_admin"):
                self._send_json({"success": False, "message": "Admin access required"}, status=HTTPStatus.FORBIDDEN)
                return
            users = list_users()
            self._send_json({"success": True, "users": users})
            return
        if self.path == "/api/backups":
            self._send_json({"backups": list_backups()})
            return
        if self.path.startswith("/api/backup/download/"):
            backup_filename = unquote(self.path[len("/api/backup/download/"):])
            
            # Reject filenames with path traversal sequences
            if ".." in backup_filename or "/" in backup_filename or "\\" in backup_filename:
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid filename")
                return
            
            backup_path = BACKUPS_DIR / backup_filename
            
            # Security check: prevent path traversal and symlink attacks
            try:
                resolved_backup = backup_path.resolve()
                resolved_backups_dir = BACKUPS_DIR.resolve()
                
                # Use is_relative_to if available (Python 3.9+), fallback to string check
                try:
                    is_within_dir = resolved_backup.is_relative_to(resolved_backups_dir)
                except AttributeError:
                    # Fallback for Python < 3.9
                    is_within_dir = str(resolved_backup).startswith(str(resolved_backups_dir) + os.sep)
                
                if not is_within_dir:
                    raise ValueError("Outside backups dir")
                
                # Check if it's a symlink (additional security)
                if backup_path.is_symlink():
                    raise ValueError("Symlinks not allowed")
                
                # Verify file exists and is a regular file
                if not resolved_backup.exists() or not resolved_backup.is_file():
                    raise ValueError("Not a valid file")
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            data = backup_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{backup_filename}"')
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/screenshots/"):
            rel_path = unquote(self.path[len("/screenshots/"):]).lstrip("/")
            if not rel_path:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            requested = (SCREENSHOTS_DIR / rel_path).resolve()
            base = SCREENSHOTS_DIR.resolve()
            try:
                if not str(requested).startswith(str(base)):
                    raise ValueError("Outside screenshots dir")
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            if not requested.exists() or not requested.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            mime, _ = mimetypes.guess_type(str(requested))
            data = requested.read_bytes()
            self._send_bytes(data, status=HTTPStatus.OK, content_type=mime or "application/octet-stream")
            return
        
        # Serve scan result files (nikto, nuclei, nmap, httpx JSON files)
        if self.path.startswith("/results/"):
            rel_path = unquote(self.path[len("/results/"):]).lstrip("/")
            if not rel_path:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            # Security: only allow JSON files with specific prefixes
            allowed_prefixes = ["nikto_", "nuclei_", "httpx_", "ffuf_"]
            if not any(rel_path.startswith(prefix) and rel_path.endswith(".json") for prefix in allowed_prefixes):
                self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
                return
            
            requested = (DATA_DIR / rel_path).resolve()
            base = DATA_DIR.resolve()
            try:
                # Prevent path traversal
                if not str(requested).startswith(str(base)):
                    raise ValueError("Outside data dir")
                # Prevent symlink attacks
                if requested.is_symlink():
                    raise ValueError("Symlinks not allowed")
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            if not requested.exists() or not requested.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            data = requested.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{rel_path}"')
            self.end_headers()
            self.wfile.write(data)
            return
        
        if self.path.startswith("/api/history/commands"):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            domain = (params.get("domain") or [""])[0].strip().lower()
            if not domain:
                self._send_json({"success": False, "message": "domain parameter required"}, status=HTTPStatus.BAD_REQUEST)
                return
            limit_param = params.get("limit")
            limit = 200
            if limit_param:
                try:
                    limit = max(1, min(2000, int(limit_param[0])))
                except (TypeError, ValueError):
                    limit = 200
            try:
                # OPTIMIZATION: Reduced from 5000 to 1000 for better performance
                # Load up to 1000 recent entries from database for command filtering
                # This is sufficient since we filter for commands (which are ~10% of logs)
                # and then slice to the requested limit (default 200, max 2000)
                events = load_domain_history(domain, limit=1000)
            except RuntimeError as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            commands = [evt for evt in events if str(evt.get("text", "")).lstrip().startswith("$")]
            payload = {"domain": domain, "commands": commands[-limit:]}
            self._send_json(payload)
            return

        if self.path.startswith("/api/history"):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            domain = (params.get("domain") or [""])[0].strip().lower()
            if not domain:
                self._send_json({"success": False, "message": "domain parameter required"}, status=HTTPStatus.BAD_REQUEST)
                return
            try:
                # Load only the last 1000 events directly from database for better performance
                events = load_domain_history(domain, limit=1000)
            except RuntimeError as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self._send_json({"domain": domain, "events": events})
            return
        if self.path == "/api/export/state":
            data = json.dumps(load_state(), indent=2).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", 'attachment; filename="state.json"')
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/api/export/csv":
            data = build_targets_csv(load_state())
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", 'attachment; filename="targets.csv"')
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/api/export/subdomains"):
            # Parse query string for filters
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)
            
            # Extract filter parameters
            filters = {
                "domain": query_params.get("domain", [""])[0],
                "domainSearch": query_params.get("domainSearch", [""])[0],
                "status": query_params.get("status", ["all"])[0],
                "maxSeverity": query_params.get("maxSeverity", ["all"])[0],
                "hasFindings": query_params.get("hasFindings", ["false"])[0].lower() == "true",
                "hasScreenshots": query_params.get("hasScreenshots", ["false"])[0].lower() == "true",
                "subSearch": query_params.get("subSearch", [""])[0],
                "statusCodes": query_params.get("statusCodes", [""])[0],
            }
            
            # Determine format from path
            if self.path.startswith("/api/export/subdomains/txt"):
                data = export_subdomains_txt(load_state(), filters)
                content_type = "text/plain"
                filename = "subdomains.txt"
            elif self.path.startswith("/api/export/subdomains/csv"):
                data = export_subdomains_csv(load_state(), filters)
                content_type = "text/csv"
                filename = "subdomains.csv"
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(data)
            return
        # Database viewer: list all tables with row counts
        if self.path == "/api/db/tables":
            try:
                db = get_db()
                with DB_LOCK:
                    cursor = db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                    tables = [row[0] for row in cursor.fetchall()]
                    result = []
                    for tbl in tables:
                        # SQLite does not support parameterized table names.
                        # The regex below ensures only safe identifiers (letters, digits,
                        # underscore, starting with a letter or underscore) are used in
                        # the f-string, preventing SQL injection.
                        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', tbl):
                            count_row = db.execute(f"SELECT COUNT(*) FROM \"{tbl}\"").fetchone()
                            result.append({"name": tbl, "row_count": count_row[0]})
                self._send_json({"success": True, "tables": result})
            except Exception as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        # Database viewer: fetch rows from a specific table
        if self.path.startswith("/api/db/table/"):
            parsed = urlparse(self.path)
            table_name = unquote(parsed.path[len("/api/db/table/"):]).strip()
            # Validate table name: only allow safe identifiers (letters, digits, underscore).
            # SQLite does not support parameterized table/column names, so all f-string
            # interpolations below rely on this check to prevent SQL injection.
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', table_name):
                self._send_json({"success": False, "message": "Invalid table name"}, status=HTTPStatus.BAD_REQUEST)
                return
            query_params = parse_qs(parsed.query)
            try:
                page = max(1, int(query_params.get("page", ["1"])[0]))
            except (ValueError, TypeError):
                page = 1
            _allowed_page_sizes = (25, 50, 100, 250, 500)
            try:
                _ps = int(query_params.get("page_size", ["50"])[0])
                page_size = _ps if _ps in _allowed_page_sizes else 50
            except (ValueError, TypeError):
                page_size = 50
            search = query_params.get("search", [""])[0].strip()
            sort_col = query_params.get("sort_col", [""])[0].strip()
            sort_dir = query_params.get("sort_dir", ["asc"])[0].strip().lower()
            # Whitelist sort direction to prevent injection via ORDER BY clause
            if sort_dir not in ("asc", "desc"):
                sort_dir = "asc"
            try:
                db = get_db()
                with DB_LOCK:
                    # Verify table exists using a parameterized query
                    exists = db.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
                    ).fetchone()
                    if not exists:
                        self._send_json({"success": False, "message": "Table not found"}, status=HTTPStatus.NOT_FOUND)
                        return
                    # Get column names — table_name is safe per regex check above;
                    # PRAGMA does not support parameterized identifiers.
                    col_cursor = db.execute(f"PRAGMA table_info(\"{table_name}\")")
                    columns = [row[1] for row in col_cursor.fetchall()]
                    if not columns:
                        self._send_json({"success": True, "columns": [], "rows": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0})
                        return
                    # Validate sort column against the actual column list to prevent injection.
                    # sort_dir is already whitelisted to "asc"/"desc" above.
                    if sort_col and sort_col in columns:
                        order_clause = f" ORDER BY \"{sort_col}\" {sort_dir.upper()}"
                    else:
                        order_clause = ""
                    # Build search filter across all columns using parameterized LIKE queries
                    where_clause = ""
                    params: List[Any] = []
                    if search:
                        conditions = [f"CAST(\"{col}\" AS TEXT) LIKE ?" for col in columns]
                        where_clause = " WHERE " + " OR ".join(conditions)
                        params = [f"%{search}%"] * len(columns)
                    count_sql = f"SELECT COUNT(*) FROM \"{table_name}\"{where_clause}"
                    total = db.execute(count_sql, params).fetchone()[0]
                    total_pages = max(1, (total + page_size - 1) // page_size)
                    offset = (page - 1) * page_size
                    data_sql = f"SELECT * FROM \"{table_name}\"{where_clause}{order_clause} LIMIT ? OFFSET ?"
                    rows_cursor = db.execute(data_sql, params + [page_size, offset])
                    rows = [list(row) for row in rows_cursor.fetchall()]
                self._send_json({
                    "success": True,
                    "table": table_name,
                    "columns": columns,
                    "rows": rows,
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages,
                })
            except Exception as exc:
                self._send_json({"success": False, "message": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
