from http.server import BaseHTTPRequestHandler
import hmac
import ipaddress
import json
import os
import socket
from urllib.parse import urlparse

from pipeline.analyze import analyze_target

MAX_REQUEST_BYTES = 16_384


def configured_list(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").replace("\n", ",").split(",") if item.strip()]


def canonical_repository(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError("Repository must be a credential-free HTTPS URL.")
    segments = [segment for segment in parsed.path.rstrip("/").removesuffix(".git").split("/") if segment]
    if len(segments) != 2 or not parsed.hostname:
        raise ValueError("Repository must identify one exact organization and repository.")
    return f"https://{parsed.hostname.lower()}/{'/'.join(segments)}"


def assert_public_host(hostname: str) -> None:
    addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ValueError("Repository host could not be resolved.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Private, local, reserved, multicast, and link-local repository addresses are blocked.")


class handler(BaseHTTPRequestHandler):
    def send_json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        expected_secret = os.environ.get("NITRO_ANALYSIS_WORKER_SECRET", "")
        supplied_secret = self.headers.get("X-Analysis-Worker-Secret", "")
        if len(expected_secret) < 32 or not hmac.compare_digest(supplied_secret, expected_secret):
            self.send_json(401, {"error": "Unauthorized worker request."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
                raise ValueError("Invalid request size.")
            body = json.loads(self.rfile.read(content_length))
            if body.get("targetType") != "repository":
                raise ValueError("Vercel source analysis supports approved repositories only.")

            requested = canonical_repository(str(body.get("source", "")))
            approved = {canonical_repository(item) for item in configured_list("NITRO_ANALYSIS_REPOSITORIES")}
            if requested not in approved:
                self.send_json(403, {"error": "Repository is not approved by the server administrator."})
                return

            assert_public_host(urlparse(requested).hostname or "")
            result = analyze_target("repository", requested, portable_clone=True)
            self.send_json(200, result)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
        except Exception:
            self.send_json(500, {"error": "Repository analysis failed."})
