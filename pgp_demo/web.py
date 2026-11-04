"""Giao diện web cục bộ cho bản mô phỏng PGP."""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import secrets
import sys
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import armor, attack, crypto
from .crypto import CryptoError
from .keys import KeyringError, Keyring, PublicIdentity, fingerprint
from .users import User, Users

STATIC_DIRECTORY = Path(__file__).with_name("static")
MAX_REQUEST_SIZE = 2_000_000
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

STEP_DETAILS = {
    "Tạo chữ ký số": "Tính H1 = SHA-256(plaintext) và dùng khóa riêng ký RSA-PSS/SHA-256 nếu bật ký. Chữ ký RSA-PSS được xác minh trực tiếp, không giải mã để lấy H1.",
    "Nén dữ liệu": "Ghép plaintext và chữ ký số, sau đó nén bằng zlib.",
    "Sinh khóa phiên": "Tạo khóa AES-256 ngẫu nhiên cho gói tin; bỏ qua nếu không bật mã hóa.",
    "Mã hóa lai": "Nếu bật mã hóa: dùng AES-256-GCM mã hóa dữ liệu nén và RSA-OAEP bọc khóa phiên bằng public key người nhận.",
    "Đóng gói ASCII armor": "Đóng envelope JSON thành Base64 để dễ sao chép. Bản demo không tạo CRC-24.",
    "Tách gói tin ASCII armor": "Giải mã Base64, đọc envelope JSON và payload. Bản demo không tạo hoặc kiểm tra CRC-24.",
    "Giải mã lấy lại khóa phiên": "Nếu gói tin được mã hóa: dùng private key người nhận và RSA-OAEP mở khóa phiên AES-256.",
    "Giải mã dữ liệu và giải nén": "Dùng khóa phiên giải mã và xác thực AES-GCM, giải nén zlib, rồi tách plaintext và chữ ký.",
    "Xác minh chữ ký số": "Tính H2 = SHA-256(plaintext nhận được) và xác minh chữ ký RSA-PSS/SHA-256 bằng public key người ký.",
}


def _identity_data(identity: PublicIdentity | None) -> dict[str, Any] | None:
    if identity is None:
        return None
    return {
        "name": identity.name,
        "fingerprint": identity.fingerprint,
        "bits": identity.public_key.key_size,
    }


def _present_step(label: str, value: str, status: str = "success") -> dict[str, str]:
    return {
        "label": label,
        "detail": STEP_DETAILS.get(label, "Thông tin xử lý của bước này."),
        "value": value,
        "status": status,
    }


class MessageOpenSession:
    def __init__(self, receiver: User, armored: str, passphrase: str) -> None:
        self.receiver = receiver
        self.armored = armored
        self.passphrase = passphrase
        self.stage = 0
        self.envelope: dict[str, Any] | None = None
        self.payload: bytes | None = None
        self.private_key: rsa.RSAPrivateKey | None = None
        self.session_key: bytes | None = None
        self.nonce: bytes | None = None
        self.message: str | None = None
        self.signature: dict[str, Any] | None = None
        self.signature_result: dict[str, str] | None = None
        self.created_at = time.monotonic()
        self.closed = False
        self.total_steps = 4

    @staticmethod
    def _step(label: str, value: str, status: str = "success") -> dict[str, str]:
        return _present_step(label, value, status)

    def advance(self, users: Users) -> tuple[dict[str, str], bool, dict[str, Any] | None]:
        if self.closed:
            raise ValueError("Phiên nhận gói tin đã kết thúc hoặc hết hạn.")
        encrypted = bool(self.envelope and self.envelope.get("encrypted") is True)
        try:
            if self.stage == 0:
                try:
                    raw_envelope = armor.decode_bytes(self.armored, "MESSAGE")
                    envelope = json.loads(raw_envelope.decode("utf-8"))
                except (ValueError, TypeError) as exc:
                    return self._fail("Tách gói tin ASCII armor", str(exc))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return self._fail(
                        "Tách gói tin ASCII armor",
                        "Base64 đã giải mã được nhưng envelope JSON không hợp lệ hoặc đã bị sửa.",
                    )
                if not isinstance(envelope, dict):
                    return self._fail("Tách gói tin ASCII armor", "Envelope phải là một đối tượng JSON.")
                if envelope.get("version") != 1 or not isinstance(envelope.get("encrypted"), bool):
                    return self._fail(
                        "Tách gói tin ASCII armor",
                        "Phiên bản hoặc cấu trúc envelope không được hỗ trợ.",
                    )
                try:
                    self.payload = bytes.fromhex(envelope["payload"])
                except (ValueError, KeyError, TypeError):
                    return self._fail("Tách gói tin ASCII armor", "Payload thiếu hoặc không đúng định dạng hex.")
                self.envelope = envelope
                return self._step_result(
                    "Tách gói tin ASCII armor",
                    f"Base64/JSON hợp lệ; đã đọc envelope và {len(self.payload)} byte payload.",
                )

            if self.stage == 1:
                if not encrypted:
                    return self._step_result(
                        "Giải mã lấy lại khóa phiên",
                        "Bỏ qua: gói tin không mã hóa, không có khóa phiên để mở.",
                    )
                try:
                    self.private_key = users.keyring(self.receiver).load_private(self.passphrase)
                except (ValueError, OSError, KeyringError) as exc:
                    return self._fail("Giải mã lấy lại khóa phiên", str(exc))
                finally:
                    self.passphrase = ""
                envelope = self.envelope or {}
                if self.private_key is None:
                    return self._fail("Giải mã lấy lại khóa phiên", "Chưa mở khóa khóa riêng người nhận.")
                if envelope.get("recipient_fingerprint") != fingerprint(self.private_key.public_key()):
                    return self._fail(
                        "Giải mã lấy lại khóa phiên",
                        "Fingerprint không khớp; gói tin không dành cho khóa riêng này.",
                    )
                try:
                    encrypted_session_key = bytes.fromhex(envelope["encrypted_session_key"])
                except (ValueError, KeyError, TypeError):
                    return self._fail(
                        "Giải mã lấy lại khóa phiên",
                        "Khối khóa phiên RSA-OAEP không hợp lệ.",
                    )
                try:
                    self.session_key = self.private_key.decrypt(
                        encrypted_session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                except (ValueError, TypeError):
                    return self._fail(
                        "Giải mã lấy lại khóa phiên",
                        "Không mở được khóa phiên: khóa hoặc dữ liệu không hợp lệ.",
                    )
                return self._step_result(
                    "Giải mã lấy lại khóa phiên",
                    "Đã dùng khóa riêng người nhận mở khóa phiên AES-256.",
                )

            if self.stage == 2:
                if encrypted:
                    try:
                        self.nonce = bytes.fromhex((self.envelope or {})["nonce"])
                    except (ValueError, KeyError, TypeError):
                        return self._fail(
                            "Giải mã dữ liệu và giải nén",
                            "Nonce AES-GCM thiếu hoặc không đúng định dạng.",
                        )
                    if self.session_key is None or self.nonce is None or self.payload is None:
                        return self._fail(
                            "Giải mã dữ liệu và giải nén",
                            "Thiếu dữ liệu để giải mã AES-GCM.",
                        )
                    try:
                        self.payload = AESGCM(self.session_key).decrypt(self.nonce, self.payload, None)
                    except InvalidTag:
                        return self._fail(
                            "Giải mã dữ liệu và giải nén",
                            "Xác thực AES-GCM thất bại: payload đã bị sửa hoặc hỏng.",
                        )
                    except ValueError:
                        return self._fail(
                            "Giải mã dữ liệu và giải nén",
                            "Khóa phiên hoặc nonce AES-GCM không hợp lệ.",
                        )
                if (self.envelope or {}).get("compression") != "zlib":
                    return self._fail(
                        "Giải mã dữ liệu và giải nén",
                        "Thuật toán nén trong gói tin không được hỗ trợ.",
                    )
                if self.payload is None:
                    return self._fail("Giải mã dữ liệu và giải nén", "Không có payload để giải nén.")
                compressed_size = len(self.payload)
                try:
                    self.payload = zlib.decompress(self.payload)
                except zlib.error:
                    return self._fail(
                        "Giải mã dữ liệu và giải nén",
                        "Giải nén zlib thất bại: dữ liệu nén đã hỏng hoặc bị sửa.",
                    )
                try:
                    content = json.loads(self.payload.decode("utf-8"))
                    self.message = content["message"]
                    self.signature = content.get("signature")
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
                    return self._fail(
                        "Giải mã dữ liệu và giải nén",
                        "Plaintext sau giải nén không có cấu trúc hợp lệ.",
                    )
                if not isinstance(self.message, str) or (
                    self.signature is not None and not isinstance(self.signature, dict)
                ):
                    return self._fail(
                        "Giải mã dữ liệu và giải nén",
                        "Plaintext hoặc chữ ký số không đúng định dạng.",
                    )
                return self._step_result(
                    "Giải mã dữ liệu và giải nén",
                    f"{'AES-256-GCM đã xác thực; ' if encrypted else ''}giải nén zlib {compressed_size} byte; đã tách plaintext và chữ ký.",
                )

            if self.stage == 3:
                if self.message is None:
                    return self._fail("Xác minh chữ ký số", "Không có plaintext để xác minh.")
                digest = hashlib.sha256(self.message.encode("utf-8")).hexdigest()
                if self.signature is None:
                    self.signature_result = {
                        "status": "unsigned",
                        "message": "Tin nhắn không có chữ ký số.",
                    }
                    return self._finish_step(
                        "Xác minh chữ ký số",
                        f"H2 = {digest}. Gói tin không có chữ ký để xác minh.",
                        "warning",
                    )
                signature = self.signature
                signer = (
                    users.keyring(self.receiver).find_public(signature.get("fingerprint", ""))
                    if isinstance(signature.get("fingerprint"), str)
                    else None
                )
                if signer is None:
                    self.signature_result = {
                        "status": "unknown",
                        "message": "Không rõ người ký. Hãy import khóa công khai của người ký để xác minh.",
                    }
                    return self._finish_step(
                        "Xác minh chữ ký số",
                        f"H2 = {digest}. Không có public key người ký; chưa thể xác minh RSA-PSS.",
                        "warning",
                    )
                if crypto.verify_signature(self.message, signature, signer.public_key):
                    self.signature_result = {
                        "status": "valid",
                        "message": f"Chữ ký hợp lệ — {signer.name} (RSA-PSS / SHA-256).",
                    }
                    return self._finish_step(
                        "Xác minh chữ ký số",
                        f"H2 = {digest}. RSA-PSS/SHA-256 hợp lệ với public key của {signer.name}.",
                        "success",
                    )
                self.signature_result = {
                    "status": "modified",
                    "message": "Chữ ký không hợp lệ — nội dung hoặc chữ ký có thể đã bị sửa.",
                }
                return self._finish_step(
                    "Xác minh chữ ký số",
                    f"H2 = {digest}. RSA-PSS không hợp lệ: nội dung hoặc chữ ký có thể đã bị sửa.",
                    "failed",
                )

            raise ValueError("Phiên nhận gói tin đã kết thúc.")
        except (ValueError, TypeError, KeyError, OSError, KeyringError, CryptoError) as exc:
            return self._fail(self._label_for_stage(), str(exc))

    def _label_for_stage(self) -> str:
        return (
            "Tách gói tin ASCII armor",
            "Giải mã lấy lại khóa phiên",
            "Giải mã dữ liệu và giải nén",
            "Xác minh chữ ký số",
        )[min(self.stage, 3)]

    def _step_result(self, label: str, value: str) -> tuple[dict[str, str], bool, dict[str, Any] | None]:
        return self._finish_step(label, value, "success")

    def _fail(self, label: str, value: str) -> tuple[dict[str, str], bool, dict[str, Any] | None]:
        return self._finish_step(label, value, "failed")

    def _finish_step(
        self, label: str, value: str, status: str
    ) -> tuple[dict[str, str], bool, dict[str, Any] | None]:
        self.stage += 1
        done = status == "failed" or self.stage == self.total_steps
        self.closed = done
        result = None
        if self.stage == self.total_steps and self.message is not None:
            result = {
                "message": self.message,
                "encrypted": (self.envelope or {}).get("encrypted") is True,
                "signature": self.signature_result,
            }
        return self._step(label, value, status), done, result


class MessageCreateSession:
    def __init__(
        self,
        message: str,
        recipient_key: rsa.RSAPublicKey | None,
        creation: crypto.MessageCreationSession | None = None,
        signer_keyring: Keyring | None = None,
        signer_fingerprint: str | None = None,
        signer_passphrase: str = "",
    ) -> None:
        self.creation = creation
        self.message = message
        self.recipient_key = recipient_key
        self.signer_keyring = signer_keyring
        self.signer_fingerprint = signer_fingerprint
        self.signer_passphrase = signer_passphrase
        self.created_at = time.monotonic()
        self.closed = False
        self.total_steps = 5

    def advance(self) -> tuple[dict[str, str], bool, dict[str, Any] | None]:
        if self.closed:
            raise ValueError("Phiên tạo gói tin đã kết thúc hoặc hết hạn.")
        if self.signer_keyring is not None:
            try:
                signer_key = self.signer_keyring.load_private(self.signer_passphrase)
            except (ValueError, OSError, KeyringError) as exc:
                self.signer_passphrase = ""
                return self._finish("Tạo chữ ký số", str(exc), "failed", None)
            self.signer_passphrase = ""
            self.creation = crypto.MessageCreationSession(
                self.message,
                self.recipient_key,
                signer_key,
                self.signer_fingerprint,
            )
            self.signer_keyring = None
        if self.creation is None:
            self.creation = crypto.MessageCreationSession(self.message, self.recipient_key)
        if not self.creation.done:
            try:
                label, value, _ = self.creation.advance()
            except (ValueError, TypeError, OSError, CryptoError) as exc:
                return self._finish(self.creation.current_label, str(exc), "failed", None)
            return self._finish(label, value, "success", None, done=False)
        try:
            armored = armor.encode("MESSAGE", self.creation.envelope)
        except (ValueError, TypeError) as exc:
            return self._finish("Đóng gói ASCII armor", str(exc), "failed", None)
        return self._finish(
            "Đóng gói ASCII armor",
            f"{len(armored.encode('utf-8'))} byte văn bản",
            "success",
            {"armored": armored},
        )

    def _finish(
        self,
        label: str,
        value: str,
        status: str,
        result: dict[str, Any] | None,
        done: bool = True,
    ) -> tuple[dict[str, str], bool, dict[str, Any] | None]:
        self.closed = done
        return _present_step(label, value, status), done, result


def _find_recipient(users: Users, sender: User, wanted: str) -> PublicIdentity | None:
    for user in users.list():
        identity = users.keyring(user).own_identity()
        if identity and identity.fingerprint == wanted:
            return identity
    return users.keyring(sender).find_public(wanted)


def create_server(data_directory: str | Path, port: int = 8000) -> ThreadingHTTPServer:
    """Tạo server chỉ lắng nghe trên loopback."""
    users = Users(data_directory)
    open_sessions: dict[str, MessageOpenSession] = {}
    open_sessions_lock = threading.Lock()
    create_sessions: dict[str, MessageCreateSession] = {}
    create_sessions_lock = threading.Lock()

    def remove_expired_sessions(sessions: dict[str, Any]) -> None:
        now = time.monotonic()
        for session_id, session in list(sessions.items()):
            if now - session.created_at > 900:
                del sessions[session_id]

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
                page_path = STATIC_DIRECTORY / "index.html"
                if not page_path.is_file():
                    self._send_error(
                        503,
                        "Giao diện chưa được build. Chạy npm --prefix frontend ci rồi npm --prefix frontend run build.",
                    )
                    return
                self._send_static_file(page_path, cache_control="no-store")
                return
            if parsed.path.startswith("/assets/"):
                relative_parts = [part for part in unquote(parsed.path).split("/") if part]
                asset_path = (STATIC_DIRECTORY / Path(*relative_parts)).resolve()
                try:
                    asset_path.relative_to(STATIC_DIRECTORY.resolve())
                except ValueError:
                    self._send_error(404, "Không tìm thấy tài nguyên.")
                    return
                if not asset_path.is_file():
                    self._send_error(404, "Không tìm thấy tài nguyên.")
                    return
                self._send_static_file(asset_path, cache_control="public, max-age=31536000, immutable")
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

        def _send_static_file(self, path: Path, cache_control: str) -> None:
            try:
                body = path.read_bytes()
            except OSError as exc:
                self._send_error(500, f"Không đọc được tài nguyên giao diện: {exc}")
                return
            content_type, _ = mimetypes.guess_type(path.name)
            if path.suffix == ".js":
                content_type = "text/javascript"
            if content_type and (content_type.startswith("text/") or content_type == "application/javascript"):
                content_type += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache_control)
            self.end_headers()
            self.wfile.write(body)

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
                if path == "/api/messages/create/next":
                    self._advance_create_message(data)
                    return
                if path == "/api/messages/open":
                    self._open_message(data)
                    return
                if path == "/api/messages/open/next":
                    self._advance_open_message(data)
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
            signer_fingerprint = None
            signer_ring = None

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
                signer_fingerprint = identity.fingerprint

            session = MessageCreateSession(
                message,
                recipient_key,
                signer_keyring=signer_ring,
                signer_fingerprint=signer_fingerprint,
                signer_passphrase=(
                    data.get("signer_passphrase")
                    if isinstance(data.get("signer_passphrase"), str)
                    else ""
                ),
            )
            if not sign:
                session.creation = crypto.MessageCreationSession(message, recipient_key)
            session_id = secrets.token_urlsafe(24)
            step, done, result = session.advance()
            with create_sessions_lock:
                remove_expired_sessions(create_sessions)
                create_sessions[session_id] = session
                if done:
                    create_sessions.pop(session_id, None)
            self._send_json(
                200,
                {
                    "session_id": session_id if not done else None,
                    "step": step,
                    "done": done,
                    "result": result,
                    "total_steps": session.total_steps,
                },
            )

        def _advance_create_message(self, data: dict[str, Any]) -> None:
            session_id = self._require_string(data, "session_id")
            with create_sessions_lock:
                remove_expired_sessions(create_sessions)
                session = create_sessions.get(session_id)
                if session is None:
                    self._send_error(404, "Phiên tạo gói tin không tồn tại hoặc đã hết hạn.")
                    return
                step, done, result = session.advance()
                if done:
                    del create_sessions[session_id]
            self._send_json(
                200,
                {
                    "session_id": None if done else session_id,
                    "step": step,
                    "done": done,
                    "result": result,
                    "total_steps": session.total_steps,
                },
            )

        def _open_message(self, data: dict[str, Any]) -> None:
            receiver = self._resolve_user(data)
            armored = self._require_string(data, "armored")
            session = MessageOpenSession(
                receiver,
                armored,
                data.get("passphrase") if isinstance(data.get("passphrase"), str) else "",
            )
            session_id = secrets.token_urlsafe(24)
            step, done, result = session.advance(users)
            with open_sessions_lock:
                remove_expired_sessions(open_sessions)
                open_sessions[session_id] = session
                if done:
                    open_sessions.pop(session_id, None)
            self._send_json(
                200,
                {
                    "session_id": session_id if not done else None,
                    "step": step,
                    "done": done,
                    "result": result,
                    "total_steps": session.total_steps,
                },
            )

        def _advance_open_message(self, data: dict[str, Any]) -> None:
            session_id = self._require_string(data, "session_id")
            with open_sessions_lock:
                remove_expired_sessions(open_sessions)
                session = open_sessions.get(session_id)
                if session is None:
                    self._send_error(404, "Phiên nhận gói tin không tồn tại hoặc đã hết hạn.")
                    return
                step, done, result = session.advance(users)
                if done:
                    del open_sessions[session_id]
            self._send_json(
                200,
                {
                    "session_id": None if done else session_id,
                    "step": step,
                    "done": done,
                    "result": result,
                    "total_steps": session.total_steps,
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
