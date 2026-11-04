"""Giao diện web cục bộ cho bản mô phỏng PGP."""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import armor, attack, crypto
from .crypto import CryptoError
from .keys import KeyringError, PublicIdentity
from .users import User, Users

PAGE_PATH = Path(__file__).with_name("templates") / "index.html"
MAX_REQUEST_SIZE = 2_000_000
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def _identity_data(identity: PublicIdentity | None) -> dict[str, Any] | None:
    if identity is None:
        return None
    return {
        "name": identity.name,
        "fingerprint": identity.fingerprint,
        "bits": identity.public_key.key_size,
    }


def _find_recipient(users: Users, sender: User, wanted: str) -> PublicIdentity | None:
    for user in users.list():
        identity = users.keyring(user).own_identity()
        if identity and identity.fingerprint == wanted:
            return identity
    return users.keyring(sender).find_public(wanted)


def create_server(data_directory: str | Path, port: int = 8000) -> ThreadingHTTPServer:
    """Tạo server chỉ lắng nghe trên loopback."""
    users = Users(data_directory)

    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "PGP-Demo"

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_error(self, status: int, message: str) -> None:
            self._send_json(status, {"error": message})

        def _read_json(self) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ValueError("Yêu cầu phải có Content-Type: application/json.")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Content-Length không hợp lệ.") from exc
            if length <= 0 or length > MAX_REQUEST_SIZE:
                raise ValueError("Kích thước yêu cầu không hợp lệ (tối đa 2 MB).")
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Nội dung JSON không hợp lệ.") from exc
            if not isinstance(payload, dict):
                raise ValueError("Nội dung yêu cầu phải là một đối tượng JSON.")
            return payload

        def _require_string(self, data: dict[str, Any], key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Trường “{key}” không được để trống.")
            return value

        def _resolve_user(self, data: dict[str, Any]) -> User:
            return users.get(self._require_string(data, "user_id"))

        def _is_local_host(self) -> bool:
            host = self.headers.get("Host", "").split(":", 1)[0].strip("[]").lower()
            return host in {"127.0.0.1", "localhost", "::1"}

        def do_GET(self) -> None:
            if not self._is_local_host():
                self._send_error(403, "Chỉ phục vụ giao diện từ máy cục bộ.")
                return
            parsed = urlparse(self.path)
            if parsed.path == "/":
                try:
                    body = PAGE_PATH.read_bytes()
                except OSError as exc:
                    self._send_error(500, f"Không đọc được giao diện: {exc}")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path != "/api/state":
                self._send_error(404, "Không tìm thấy trang hoặc API.")
                return
            try:
                query = parse_qs(parsed.query)
                requested_id = query.get("user_id", [""])[0]
                selected = users.get(requested_id) if requested_id else None
                people = []
                for user in users.list():
                    keyring = users.keyring(user)
                    identity = keyring.own_identity()
                    people.append(
                        {
                            "id": user.user_id,
                            "name": user.name,
                            "key": _identity_data(identity),
                        }
                    )
                contacts = (
                    [_identity_data(item) for item in users.keyring(selected).list_contacts()]
                    if selected
                    else []
                )
                self._send_json(
                    200,
                    {
                        "users": people,
                        "selected_user_id": selected.user_id if selected else None,
                        "contacts": contacts,
                    },
                )
            except (ValueError, OSError, KeyringError) as exc:
                self._send_error(400, str(exc))

        def do_POST(self) -> None:
            if not self._is_local_host():
                self._send_error(403, "Chỉ chấp nhận yêu cầu từ máy cục bộ.")
                return
            try:
                data = self._read_json()
                path = urlparse(self.path).path
                if path == "/api/users":
                    user = users.add(self._require_string(data, "name"))
                    self._send_json(201, {"user": {"id": user.user_id, "name": user.name}})
                    return
                if path == "/api/keys/generate":
                    user = self._resolve_user(data)
                    passphrase = self._require_string(data, "passphrase")
                    bits = data.get("bits")
                    if isinstance(bits, bool) or not isinstance(bits, int):
                        raise ValueError("Kích thước RSA phải là số nguyên 2048 hoặc 4096.")
                    key_fingerprint = users.keyring(user).generate(passphrase, bits)
                    self._send_json(201, {"fingerprint": key_fingerprint, "bits": bits})
                    return
                if path == "/api/keys/export":
                    user = self._resolve_user(data)
                    self._send_json(200, {"armored": users.keyring(user).export_public()})
                    return
                if path == "/api/keys/import":
                    user = self._resolve_user(data)
                    identity = users.keyring(user).import_public(
                        self._require_string(data, "armored")
                    )
                    self._send_json(201, {"key": _identity_data(identity)})
                    return
                if path == "/api/messages/create":
                    self._create_message(data)
                    return
                if path == "/api/messages/open":
                    self._open_message(data)
                    return
                if path == "/api/attack/tamper":
                    modified = attack.tamper_package(self._require_string(data, "armored"))
                    self._send_json(200, {"armored": modified})
                    return
                if path == "/api/attack/eve":
                    self._try_eve(data)
                    return
                self._send_error(404, "Không tìm thấy API.")
            except (ValueError, OSError, KeyringError, CryptoError) as exc:
                self._send_error(400, str(exc))

        def _create_message(self, data: dict[str, Any]) -> None:
            sender = users.get(self._require_string(data, "sender_id"))
            message = self._require_string(data, "message")
            encrypt = data.get("encrypt") is True
            sign = data.get("sign") is True
            recipient_key = None
            signer_key = None
            signer_fingerprint = None

            if encrypt:
                recipient_fingerprint = self._require_string(data, "recipient_fingerprint")
                recipient = _find_recipient(users, sender, recipient_fingerprint)
                if recipient is None:
                    raise ValueError("Không tìm thấy khóa công khai người nhận đã chọn.")
                recipient_key = recipient.public_key

            if sign:
                signer = users.get(self._require_string(data, "signer_id"))
                signer_ring = users.keyring(signer)
                identity = signer_ring.own_identity()
                if identity is None:
                    raise ValueError(f"{signer.name} chưa có khóa để ký.")
                signer_key = signer_ring.load_private(
                    self._require_string(data, "signer_passphrase")
                )
                signer_fingerprint = identity.fingerprint

            envelope, steps = crypto.create_message(
                message,
                recipient_key,
                signer_key,
                signer_fingerprint,
            )
            self._send_json(
                200,
                {
                    "armored": armor.encode("MESSAGE", envelope),
                    "steps": [{"label": label, "value": value} for label, value in steps],
                },
            )

        def _open_message(self, data: dict[str, Any]) -> None:
            receiver = self._resolve_user(data)
            envelope = armor.decode(self._require_string(data, "armored"), "MESSAGE")
            if not isinstance(envelope, dict):
                raise CryptoError("Cấu trúc gói tin không hợp lệ.")
            private_key = None
            if envelope.get("encrypted"):
                private_key = users.keyring(receiver).load_private(
                    self._require_string(data, "passphrase")
                )
            message, signature = crypto.decrypt_message(envelope, private_key)
            signature_result: dict[str, str] = {"status": "unsigned", "message": "Tin nhắn không có chữ ký."}
            if signature is not None:
                fingerprint = signature.get("fingerprint", "")
                signer = (
                    users.keyring(receiver).find_public(fingerprint)
                    if isinstance(fingerprint, str)
                    else None
                )
                if signer is None:
                    signature_result = {
                        "status": "unknown",
                        "message": "Không rõ người ký. Hãy import khóa công khai của người ký để xác minh.",
                    }
                elif crypto.verify_signature(message, signature, signer.public_key):
                    signature_result = {
                        "status": "valid",
                        "message": f"Chữ ký hợp lệ — {signer.name} (RSA-PSS / SHA-256).",
                    }
                else:
                    signature_result = {
                        "status": "modified",
                        "message": "Chữ ký không hợp lệ — nội dung hoặc chữ ký có thể đã bị sửa.",
                    }
            self._send_json(
                200,
                {
                    "message": message,
                    "encrypted": envelope.get("encrypted") is True,
                    "signature": signature_result,
                },
            )

        def _try_eve(self, data: dict[str, Any]) -> None:
            eve = next(
                (user for user in users.list() if user.name.casefold() == "eve"),
                None,
            )
            if eve is None:
                raise ValueError("Không tìm thấy người dùng tên Eve.")
            armored = self._require_string(data, "armored")
            envelope = armor.decode(armored, "MESSAGE")
            if not isinstance(envelope, dict):
                raise CryptoError("Cấu trúc gói tin không hợp lệ.")
            if not envelope.get("encrypted"):
                message, _ = crypto.decrypt_message(envelope)
                self._send_json(200, {"success": True, "message": message})
                return
            private_key = users.keyring(eve).load_private(
                self._require_string(data, "passphrase")
            )
            message, _ = crypto.decrypt_message(envelope, private_key)
            self._send_json(200, {"success": True, "message": message})

        def log_message(self, format: str, *args: Any) -> None:
            sys.stdout.write("%s - %s\n" % (self.address_string(), format % args))

    return ThreadingHTTPServer(("127.0.0.1", port), RequestHandler)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Local web interface for PGP Demo.")
    parser.add_argument("--data-dir", type=Path, help="Thư mục lưu người dùng và keyring.")
    parser.add_argument("--port", type=int, default=8000, help="Cổng giao diện (mặc định 8000).")
    args = parser.parse_args()
    data_directory = args.data_dir or Path(__file__).resolve().parent.parent / "data"
    server = create_server(data_directory, args.port)
    print(f"PGP Demo đang chạy tại http://127.0.0.1:{server.server_port}")
    print("Nhấn Ctrl+C để dừng.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐang dừng máy chủ...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
