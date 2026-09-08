"""CommandCenterHandler composition."""
class CommandCenterHandler(HandlerAuthMixin, HandlerAgentMixin, HandlerGetMixin, HandlerPostOpsMixin, HandlerPostMixin, BaseHTTPRequestHandler):
    server_version = "ReconCommandCenter/1.0"

    def log_message(self, format: str, *args) -> None:
        log(f"HTTP {self.address_string()} - {format % args}")

