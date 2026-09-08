"""HTTP handler mixin: HandlerAuthMixin."""
class HandlerAuthMixin:
    def _get_session_token(self) -> Optional[str]:
        """Extract session token from Cookie header."""
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        
        # Parse cookies
        cookies = {}
        for item in cookie_header.split(";"):
            item = item.strip()
            if "=" in item:
                key, value = item.split("=", 1)
                cookies[key.strip()] = value.strip()
        
        return cookies.get("session_token")
    
    def _get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current authenticated user from session."""
        token = self._get_session_token()
        if not token:
            return None
        return validate_session(token)
    
    def _require_auth(self) -> Optional[Dict[str, Any]]:
        """Check authentication and return user or send login page."""
        user = self._get_current_user()
        if not user:
            self._send_login_page()
            return None
        return user
    
    def _require_admin(self) -> Optional[Dict[str, Any]]:
        """Check admin authentication and return user or send error."""
        user = self._get_current_user()
        if not user:
            self._send_login_page()
            return None
        if not user.get("is_admin"):
            self._send_json({"success": False, "message": "Admin access required"}, status=HTTPStatus.FORBIDDEN)
            return None
        return user
    
    def _send_login_page(self) -> None:
        """Send the login page."""
        html = load_login_html()
        self._send_bytes(html.encode("utf-8"))

    def _send_bytes(self, payload: bytes, status: HTTPStatus = HTTPStatus.OK, content_type: str = "text/html") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self._send_bytes(data, status=status, content_type="application/json")
