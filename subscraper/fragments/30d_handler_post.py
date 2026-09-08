"""HTTP handler mixin: HandlerPostMixin."""
class HandlerPostMixin:
    def _post_public_and_users(self) -> bool:
        # Public auth endpoints (no auth required)
        if self.path == "/api/auth/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else ""
            
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"success": False, "message": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            username = payload.get("username", "").strip()
            password = payload.get("password", "").strip()
            
            if not username or not password:
                self._send_json({"success": False, "message": "Username and password are required"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            user = authenticate_user(username, password)
            if user:
                token = create_session(user)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session_token={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TIMEOUT_HOURS * 3600}")
                response = json.dumps({"success": True, "message": "Login successful", "user": {"username": user["username"], "is_admin": user["is_admin"]}}).encode("utf-8")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                return True
            else:
                self._send_json({"success": False, "message": "Invalid username or password"}, status=HTTPStatus.UNAUTHORIZED)
                return True
        
        if self.path == "/api/auth/logout":
            token = self._get_session_token()
            if token:
                delete_session(token)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            response = json.dumps({"success": True, "message": "Logged out"}).encode("utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return True
        
        # Bug bounty agent API - authenticates via scoped API key or session
        if self.path == "/api/agent" or self.path.startswith("/api/agent/") or self.path.startswith("/api/agent?"):
            self._handle_agent_post()
            return True

        # All other endpoints require authentication
        user = self._require_auth()
        if not user:
            return True
        
        # User management endpoints (admin only)
        if self.path == "/api/users/create":
            admin = self._require_admin()
            if not admin:
                return True
            
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else ""
            
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"success": False, "message": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            username = payload.get("username", "").strip()
            password = payload.get("password", "").strip()
            is_admin = payload.get("is_admin", False)
            
            success, message = create_user(username, password, is_admin=is_admin)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return True
        
        if self.path == "/api/users/edit":
            admin = self._require_admin()
            if not admin:
                return True
            
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else ""
            
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"success": False, "message": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            user_id = payload.get("user_id")
            if not user_id:
                self._send_json({"success": False, "message": "User ID is required"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                self._send_json({"success": False, "message": "Invalid user ID"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            username = payload.get("username", "").strip() or None
            password = payload.get("password", "").strip() or None
            is_admin = payload.get("is_admin") if "is_admin" in payload else None
            
            success, message = update_user(user_id, username=username, password=password, is_admin=is_admin)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return True
        
        if self.path == "/api/users/delete":
            admin = self._require_admin()
            if not admin:
                return True
            
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else ""
            
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"success": False, "message": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            user_id = payload.get("user_id")
            if not user_id:
                self._send_json({"success": False, "message": "User ID is required"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                self._send_json({"success": False, "message": "Invalid user ID"}, status=HTTPStatus.BAD_REQUEST)
                return True
            
            success, message = delete_user(user_id)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return True
        return False

    def do_POST(self):
        if self._post_public_and_users():
            return
        self._post_ops()
