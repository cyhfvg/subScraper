"""HTTP handler mixin: HandlerAgentMixin."""
class HandlerAgentMixin:
    # ------------------------------------------------------------------
    # Bug bounty agent API (/api/agent/*)
    # ------------------------------------------------------------------

    def _agent_read_json(self) -> Tuple[bool, Dict[str, Any]]:
        """Read a JSON (or form-encoded) request body. Returns (ok, payload)."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if length > 20 * 1024 * 1024:
            self._send_json({"success": False, "error": "payload_too_large",
                             "message": "Request body too large."},
                            status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return False, {}
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        if not body:
            return True, {}
        content_type = self.headers.get("Content-Type", "")
        try:
            if "application/x-www-form-urlencoded" in content_type:
                return True, {k: v[0] for k, v in parse_qs(body).items()}
            return True, json.loads(body)
        except (json.JSONDecodeError, ValueError):
            self._send_json({"success": False, "error": "invalid_json",
                             "message": "Request body must be valid JSON."},
                            status=HTTPStatus.BAD_REQUEST)
            return False, {}

    def _agent_principal(self) -> Optional[Dict[str, Any]]:
        """
        Resolve the caller: a scoped API key (Authorization: Bearer / X-API-Key)
        or a logged-in UI session. Returns None when unauthenticated.
        """
        raw_key = ""
        auth_header = self.headers.get("Authorization") or ""
        if auth_header.lower().startswith("bearer "):
            raw_key = auth_header[7:].strip()
        if not raw_key:
            raw_key = (self.headers.get("X-API-Key") or "").strip()

        if raw_key:
            record = validate_agent_api_key(raw_key)
            if not record:
                return None
            return {
                "type": "api_key",
                "name": record["name"],
                "key_id": record["key_id"],
                "scopes": list(record["scopes"]),
                "programs": list(record["programs"]),
                "expires_at": record["expires_at"],
            }

        user = self._get_current_user()
        if user:
            scopes = list(AGENT_API_SCOPES) if user.get("is_admin") else list(AGENT_SESSION_SCOPES)
            return {
                "type": "session",
                "name": user.get("username"),
                "key_id": None,
                "scopes": scopes,
                "programs": [],
                "is_admin": bool(user.get("is_admin")),
            }
        return None

    def _agent_authorize(self, required_scope: str, program_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Authenticate and enforce scope plus per-key program restrictions."""
        principal = self._agent_principal()
        if not principal:
            self._send_json({
                "success": False,
                "error": "unauthorized",
                "message": "Provide a scoped API key via 'Authorization: Bearer <key>' or 'X-API-Key'.",
            }, status=HTTPStatus.UNAUTHORIZED)
            return None

        if required_scope and required_scope not in principal["scopes"]:
            self._send_json({
                "success": False,
                "error": "insufficient_scope",
                "message": f"This key lacks the '{required_scope}' scope.",
                "required_scope": required_scope,
                "granted_scopes": principal["scopes"],
            }, status=HTTPStatus.FORBIDDEN)
            return None

        allowed_programs = principal.get("programs") or []
        if program_id and allowed_programs and program_id not in allowed_programs:
            self._send_json({
                "success": False,
                "error": "program_forbidden",
                "message": f"This key is not scoped to program '{program_id}'.",
                "allowed_programs": allowed_programs,
            }, status=HTTPStatus.FORBIDDEN)
            return None

        return principal

    def _agent_program_or_404(self, program_id: str) -> Optional[Dict[str, Any]]:
        program = get_program(program_id)
        if not program:
            self._send_json({"success": False, "error": "not_found",
                             "message": f"Program '{program_id}' not found."},
                            status=HTTPStatus.NOT_FOUND)
            return None
        return program

    def _agent_not_found(self) -> None:
        self._send_json({"success": False, "error": "not_found",
                         "message": "Unknown agent API endpoint. GET /api/agent for the endpoint index."},
                        status=HTTPStatus.NOT_FOUND)

    @staticmethod
    def _agent_index() -> Dict[str, Any]:
        return {
            "success": True,
            "service": "recon-command-center agent API",
            "auth": "Authorization: Bearer <api_key>  (or X-API-Key: <api_key>)",
            "scopes": AGENT_API_SCOPES,
            "endpoints": {
                "GET /api/agent/whoami": "Identity and granted scopes for the presented key",
                "GET /api/agent/keys": "List API keys (keys:manage)",
                "POST /api/agent/keys": "Create a scoped API key (keys:manage)",
                "POST /api/agent/keys/revoke": "Revoke a key by key_id (keys:manage)",
                "POST /api/agent/keys/delete": "Delete a key by key_id (keys:manage)",
                "GET /api/agent/programs": "List programs (programs:read)",
                "POST /api/agent/programs": "Create a program from a full scope (programs:write)",
                "GET /api/agent/programs/{id}": "Program detail incl. derived root targets (programs:read)",
                "POST /api/agent/programs/{id}": "Update a program (programs:write)",
                "POST /api/agent/programs/{id}/delete": "Delete a program (programs:write)",
                "POST /api/agent/programs/{id}/investigate": "Run recon over the whole scope (scan:run)",
                "GET /api/agent/programs/{id}/status": "Per-target pipeline progress and coverage (programs:read)",
                "GET /api/agent/programs/{id}/assets": "Discovered hosts, filterable + paginated (assets:read)",
                "GET /api/agent/programs/{id}/endpoints": "Archived/JS URLs and parameters (assets:read)",
                "GET /api/agent/programs/{id}/findings": "Normalized nuclei/nikto/JS findings (findings:read)",
                "GET /api/agent/programs/{id}/surface": "Ranked attack surface with reasons (findings:read)",
                "GET /api/agent/programs/{id}/scope": "Resolved scope and root targets (programs:read)",
                "POST /api/agent/programs/{id}/scope/check": "Check assets against program scope (programs:read)",
                "POST /api/agent/scope/check": "Check assets against an ad-hoc scope (programs:read)",
            },
        }

    def _handle_agent_get(self) -> None:
        parsed = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        segments = [seg for seg in parsed.path.strip("/").split("/")[2:] if seg]

        if not segments:
            self._send_json(self._agent_index())
            return

        if segments == ["whoami"]:
            principal = self._agent_authorize("")
            if not principal:
                return
            self._send_json({"success": True, "principal": principal})
            return

        if segments == ["keys"]:
            if not self._agent_authorize("keys:manage"):
                return
            self._send_json({"success": True, "keys": list_agent_api_keys(), "scopes": AGENT_API_SCOPES})
            return

        if segments == ["programs"]:
            principal = self._agent_authorize("programs:read")
            if not principal:
                return
            programs = list_programs()
            allowed = principal.get("programs") or []
            if allowed:
                programs = [p for p in programs if p["id"] in allowed]
            for program in programs:
                program["root_targets"] = program_root_targets(program)
            self._send_json({"success": True, "programs": programs, "count": len(programs)})
            return

        if segments[0] == "programs" and len(segments) >= 2:
            program_id = unquote(segments[1])
            sub = segments[2:]

            scope_needed = "programs:read"
            if sub[:1] == ["assets"] or sub[:1] == ["endpoints"]:
                scope_needed = "assets:read"
            elif sub[:1] in (["findings"], ["surface"]):
                scope_needed = "findings:read"

            if not self._agent_authorize(scope_needed, program_id=program_id):
                return
            program = self._agent_program_or_404(program_id)
            if not program:
                return

            if not sub:
                detail = dict(program)
                detail["root_targets"] = program_root_targets(program)
                self._send_json({"success": True, "program": detail})
                return
            if sub == ["scope"]:
                self._send_json({
                    "success": True,
                    "program_id": program_id,
                    "scope": program["scope"],
                    "root_targets": program_root_targets(program),
                    "wildcard_rule": "'*.example.com' matches example.com and every subdomain; out-of-scope always wins.",
                })
                return
            if sub == ["status"]:
                self._send_json({"success": True, **program_status(program)})
                return
            if sub == ["assets"]:
                self._send_json({"success": True, **program_assets(program, params)})
                return
            if sub == ["endpoints"]:
                self._send_json({"success": True, **program_endpoints(program, params)})
                return
            if sub == ["findings"]:
                self._send_json({"success": True, **program_findings(program, params)})
                return
            if sub == ["surface"]:
                self._send_json({"success": True, **program_surface(program, params.get("limit", 50))})
                return

        self._agent_not_found()

    def _handle_agent_post(self) -> None:
        parsed = urlparse(self.path)
        segments = [seg for seg in parsed.path.strip("/").split("/")[2:] if seg]
        if not segments:
            self._agent_not_found()
            return

        # --- API key management ---
        if segments[0] == "keys":
            principal = self._agent_authorize("keys:manage")
            if not principal:
                return
            ok, payload = self._agent_read_json()
            if not ok:
                return

            if segments == ["keys"]:
                success, message, key = create_agent_api_key(
                    payload.get("name", ""),
                    payload.get("scopes", []),
                    payload.get("programs"),
                    payload.get("expires_days"),
                    created_by=principal.get("name"),
                )
                self._send_json({"success": success, "message": message, "key": key},
                                status=HTTPStatus.CREATED if success else HTTPStatus.BAD_REQUEST)
                return
            if segments == ["keys", "revoke"]:
                success, message = revoke_agent_api_key(payload.get("key_id", ""))
                self._send_json({"success": success, "message": message},
                                status=HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST)
                return
            if segments == ["keys", "delete"]:
                success, message = delete_agent_api_key(payload.get("key_id", ""))
                self._send_json({"success": success, "message": message},
                                status=HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST)
                return
            self._agent_not_found()
            return

        # --- Ad-hoc scope check (no program needed) ---
        if segments == ["scope", "check"]:
            if not self._agent_authorize("programs:read"):
                return
            ok, payload = self._agent_read_json()
            if not ok:
                return
            in_scope = _clean_scope_list(payload.get("in_scope"))
            out_of_scope = _clean_scope_list(payload.get("out_of_scope"))
            assets = _clean_scope_list(payload.get("assets") or payload.get("asset"))
            if not assets:
                self._send_json({"success": False, "error": "missing_assets",
                                 "message": "Provide 'assets' (list) or 'asset' (string)."},
                                status=HTTPStatus.BAD_REQUEST)
                return
            results = [evaluate_asset_scope(asset, in_scope, out_of_scope) for asset in assets]
            self._send_json({"success": True, "results": results,
                             "in_scope_count": sum(1 for r in results if r["in_scope"])})
            return

        # --- Program create ---
        if segments == ["programs"]:
            if not self._agent_authorize("programs:write"):
                return
            ok, payload = self._agent_read_json()
            if not ok:
                return
            success, message, program = create_program(payload)
            if success and program:
                program["root_targets"] = program_root_targets(program)
            self._send_json({"success": success, "message": message, "program": program},
                            status=HTTPStatus.CREATED if success else HTTPStatus.BAD_REQUEST)
            return

        if segments[0] == "programs" and len(segments) >= 2:
            program_id = unquote(segments[1])
            sub = segments[2:]

            scope_needed = "programs:write"
            if sub[:1] == ["investigate"]:
                scope_needed = "scan:run"
            elif sub[:1] == ["scope"]:
                scope_needed = "programs:read"

            if not self._agent_authorize(scope_needed, program_id=program_id):
                return
            ok, payload = self._agent_read_json()
            if not ok:
                return
            program = self._agent_program_or_404(program_id)
            if not program:
                return

            if not sub:
                success, message, updated = update_program(program_id, payload)
                if success and updated:
                    updated["root_targets"] = program_root_targets(updated)
                self._send_json({"success": success, "message": message, "program": updated},
                                status=HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST)
                return
            if sub == ["delete"]:
                success, message = delete_program(program_id)
                self._send_json({"success": success, "message": message},
                                status=HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST)
                return
            if sub == ["investigate"]:
                success, message, info = investigate_program(program, payload)
                self._send_json({"success": success, "message": message, **info,
                                 "status_url": f"/api/agent/programs/{program_id}/status"},
                                status=HTTPStatus.ACCEPTED if success else HTTPStatus.BAD_REQUEST)
                return
            if sub == ["scope", "check"]:
                assets = _clean_scope_list(payload.get("assets") or payload.get("asset"))
                if not assets:
                    self._send_json({"success": False, "error": "missing_assets",
                                     "message": "Provide 'assets' (list) or 'asset' (string)."},
                                    status=HTTPStatus.BAD_REQUEST)
                    return
                results = [evaluate_asset_scope(asset, program["scope"].get("in_scope", []),
                                                program["scope"].get("out_of_scope", []))
                           for asset in assets]
                self._send_json({"success": True, "program_id": program_id, "results": results,
                                 "in_scope_count": sum(1 for r in results if r["in_scope"])})
                return

        self._agent_not_found()
