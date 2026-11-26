"""Host-side sandbox broker. Serves scan requests concurrently, up to MAX_CONCURRENT_SCANS, and returns a verdict.

Run on the host, not inside the API container:
    set SANDBOX_BROKER_TOKEN=<secret>
    python -m sandbox_broker.main
"""

from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import threading
from typing import Any

from sandbox_broker.config import BrokerConfig
from sandbox_broker.docker_runner import run_scan_container, scanner_image_status

TOKEN_HEADER = "X-Broker-Token"
RUN_PATH = "/run"
HEALTH_PATH = "/health"
MAX_CONCURRENT_SCANS = 4
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def _block(reason: str) -> dict[str, Any]:
    return {
        "verdict": "block",
        "status": "blocked",
        "executor": "docker",
        "reason": reason,
        "reasons": [
            {
                "code": reason,
                "category": "sandbox",
                "severity": "critical",
                "detail": reason,
                "risk_delta": 70,
            }
        ],
        "risk_score": 100,
        "untrusted": True,
        "released_text": None,
    }


def _clamp_timeout(value: Any, config: BrokerConfig) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value) or value <= 0:
        return config.timeout_seconds
    return min(float(value), config.max_timeout_seconds)


def _validate_request(request: dict[str, Any]) -> str | None:
    allowed_keys = {
        "action_type",
        "target",
        "payload",
        "timeout_seconds",
        "read_only_fs",
        "network_enabled",
    }
    unknown_keys = set(request) - allowed_keys
    if unknown_keys:
        return "unknown_request_fields"
    if request.get("action_type") != "scan":
        return "action_not_allowed"
    target = request.get("target")
    if not isinstance(target, str) or not target.strip() or len(target) > 512:
        return "invalid_request"
    payload = request.get("payload")
    if not isinstance(payload, dict):
        return "invalid_request"
    try:
        payload_size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return "invalid_request"
    if payload_size > 2_097_152:
        return "invalid_request"
    if request.get("network_enabled", False) is not False:
        return "network_not_allowed"
    if request.get("read_only_fs", True) is not True:
        return "read_only_required"
    timeout = request.get("timeout_seconds")
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            return "invalid_request"
        if not math.isfinite(float(timeout)) or float(timeout) <= 0:
            return "invalid_request"
    return None


def decide(config: BrokerConfig, request: dict[str, Any]) -> dict[str, Any]:
    validation_error = _validate_request(request)
    if validation_error is not None:
        return _block(validation_error)

    action_type = request["action_type"]
    target = request["target"].strip()
    payload = request["payload"]

    if scanner_image_status(config) != "ready":
        return _block("scanner_image_not_ready")
    scanner_input = json.dumps({"action_type": action_type, "target": target, "payload": payload}).encode("utf-8")
    timeout_seconds = _clamp_timeout(request.get("timeout_seconds"), config)
    if not _scan_slots.acquire(timeout=timeout_seconds):
        return _block("broker_busy")
    try:
        result = run_scan_container(config, scanner_input, timeout_seconds)
    finally:
        _scan_slots.release()
    if result.verdict == "allow":
        return {
            "verdict": "allow",
            "status": "completed",
            "executor": "docker",
            "reason": result.reason,
            "reasons": list(result.reasons),
            "risk_score": result.risk_score,
            "untrusted": False,
            "released_text": result.released_text,
        }
    return {
        "verdict": "block",
        "status": "blocked",
        "executor": "docker",
        "reason": result.reason,
        "reasons": list(result.reasons),
        "risk_score": max(result.risk_score, 70),
        "untrusted": True,
        "released_text": None,
    }


class BrokerHandler(BaseHTTPRequestHandler):
    server: BrokerHTTPServer
    server_version = "IronClawSandboxBroker"

    def do_GET(self) -> None:
        if self.path != HEALTH_PATH:
            self._send_json(404, {"error": "not_found"})
            return
        config = self.server.broker_config
        scanner_image = scanner_image_status(config)
        ready = scanner_image == "ready"
        self._send_json(
            200,
            {
                "status": "ok",
                "scanner_image": scanner_image,
                "prompt_guard_model": "ready" if ready else "not_ready",
                "policy_snapshot": "ready" if ready else "not_ready",
            },
        )

    def do_POST(self) -> None:
        if self.path != RUN_PATH:
            self._send_json(404, {"error": "not_found"})
            return
        config = self.server.broker_config
        supplied = self.headers.get(TOKEN_HEADER, "")
        if not hmac.compare_digest(supplied.encode("utf-8"), config.token.encode("utf-8")):
            self._send_json(401, {"error": "unauthorized"})
            return

        body = self._read_body(config.max_request_bytes)
        if body is None:
            self._send_json(400, {"error": "invalid_length"})
            return
        try:
            request = json.loads(body)
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._send_json(400, {"error": "invalid_json"})
            return
        if not isinstance(request, dict):
            self._send_json(400, {"error": "invalid_request"})
            return
        self._send_json(200, decide(config, request))

    def _read_body(self, limit: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        return self.rfile.read(length)

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class BrokerHTTPServer(ThreadingHTTPServer):
    def __init__(self, config: BrokerConfig) -> None:
        super().__init__((config.bind_host, config.port), BrokerHandler)
        self.broker_config = config


def main() -> None:
    config = BrokerConfig.from_env()
    server = BrokerHTTPServer(config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
