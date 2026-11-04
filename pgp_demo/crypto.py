"""Mã hóa lai, chữ ký số và xác minh chữ ký cho bản mô phỏng."""

from __future__ import annotations

import hashlib
import json
import os
import zlib
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import fingerprint


class CryptoError(ValueError):
    """Gói tin sai, bị sửa hoặc không thể giải mã."""


class MessageCreationSession:
    def __init__(
        self,
        message: str,
        recipient_public_key: rsa.RSAPublicKey | None = None,
        signing_private_key: rsa.RSAPrivateKey | None = None,
        signer_fingerprint: str | None = None,
    ) -> None:
        if not isinstance(message, str) or not message:
            raise CryptoError("Nội dung tin nhắn không được để trống.")
        if (signing_private_key is None) != (signer_fingerprint is None):
            raise CryptoError("Cần có cả khóa ký lẫn fingerprint người ký.")
        self.message = message
        self.message_bytes: bytes | None = None
        self.recipient_public_key = recipient_public_key
        self.signing_private_key = signing_private_key
        self.signer_fingerprint = signer_fingerprint
        self.signature: dict[str, str] | None = None
        self.compressed: bytes | None = None
        self.session_key: bytes | None = None
        self.nonce: bytes | None = None
        self.content = b""
        self.ciphertext = b""
        self.envelope: dict[str, Any] = {
            "version": 1,
            "encrypted": recipient_public_key is not None,
            "compression": "zlib",
            "payload": "",
            "recipient_fingerprint": None,
            "encrypted_session_key": None,
            "nonce": None,
        }
        self.steps: list[tuple[str, str]] = []
        self.operations = [
            self._create_signature,
            self._compress_content,
            self._generate_session_key,
            self._encrypt_hybrid,
        ]
        self.index = 0

    @property
    def done(self) -> bool:
        return self.index == len(self.operations)

    @property
    def current_label(self) -> str:
        if self.index >= len(self.operations):
            return "Tạo gói tin"
        labels = {
            "_create_signature": "Tạo chữ ký số",
            "_compress_content": "Nén dữ liệu",
            "_generate_session_key": "Sinh khóa phiên",
            "_encrypt_hybrid": "Mã hóa lai",
        }
        return labels[self.operations[self.index].__name__]

    def advance(self) -> tuple[str, str, bool]:
        if self.done:
            raise CryptoError("Quy trình tạo gói tin đã hoàn tất.")
        label, value = self.operations[self.index]()
        self.steps.append((label, value))
        self.index += 1
        return label, value, self.done

    def _hash(self) -> tuple[str, str]:
        try:
            self.message_bytes = self.message.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CryptoError("Nội dung có ký tự không thể mã hóa UTF-8.") from exc
        digest = hashlib.sha256(self.message_bytes).hexdigest()
        return "H1 (SHA-256 nội dung gửi)", digest

    def _sign(self) -> tuple[str, str]:
        if self.signing_private_key is None:
            return "Chữ ký", "Không ký tin nhắn"
        if self.message_bytes is None:
            raise CryptoError("Chưa băm nội dung trước khi ký.")
        signature_bytes = self.signing_private_key.sign(
            self.message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        self.signature = {
            "fingerprint": self.signer_fingerprint or "",
            "algorithm": "RSA-PSS-SHA256",
            "value": signature_bytes.hex(),
        }
        return "Chữ ký RSA-PSS", signature_bytes.hex()

    def _pack(self) -> tuple[str, str]:
        content = json.dumps(
            {"message": self.message, "signature": self.signature},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.content = content
        return "Đóng gói nội dung và chữ ký", f"{len(content)} byte UTF-8"

    def _compress(self) -> tuple[str, str]:
        self.compressed = zlib.compress(self.content)
        if self.recipient_public_key is None:
            self.envelope["payload"] = self.compressed.hex()
        return "Nén zlib", f"{len(self.content)} byte → {len(self.compressed)} byte"

    def _generate_session_key(self) -> tuple[str, str]:
        if self.recipient_public_key is None:
            return "Sinh khóa phiên", "Bỏ qua: không chọn mã hóa."
        self.session_key = AESGCM.generate_key(bit_length=256)
        self.nonce = os.urandom(12)
        return "Sinh khóa phiên", "Đã tạo khóa đối xứng AES-256 ngẫu nhiên cho phiên này."

    def _encrypt(self) -> tuple[str, str]:
        if self.session_key is None or self.nonce is None or self.compressed is None:
            raise CryptoError("Thiếu khóa phiên hoặc dữ liệu nén để mã hóa.")
        ciphertext = AESGCM(self.session_key).encrypt(self.nonce, self.compressed, None)
        self.ciphertext = ciphertext
        self.envelope["payload"] = ciphertext.hex()
        return (
            "Mã hóa AES-256-GCM",
            f"{len(self.compressed)} byte → {len(ciphertext)} byte; nonce: {self.nonce.hex()}",
        )

    def _wrap_session_key(self) -> tuple[str, str]:
        if self.recipient_public_key is None or self.session_key is None or self.nonce is None:
            raise CryptoError("Thiếu dữ liệu để bọc khóa phiên bằng RSA-OAEP.")
        encrypted_session_key = self.recipient_public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        self.envelope.update(
            {
                "recipient_fingerprint": fingerprint(self.recipient_public_key),
                "encrypted_session_key": encrypted_session_key.hex(),
                "nonce": self.nonce.hex(),
            }
        )
        return "Khóa phiên bọc bằng RSA-OAEP", encrypted_session_key.hex()

    def _encrypted_payload(self) -> tuple[str, str]:
        if not self.ciphertext:
            raise CryptoError("Payload AES-GCM chưa được tạo.")
        return "Payload AES-GCM", f"{len(self.ciphertext)} byte (đã mã hóa)"

    def _plain_payload(self) -> tuple[str, str]:
        if self.compressed is None:
            raise CryptoError("Payload nén chưa được tạo.")
        return "Payload", f"{len(self.compressed)} byte (chưa mã hóa)"

    def _create_signature(self) -> tuple[str, str]:
        _, digest = self._hash()
        _, signature = self._sign()
        if self.signing_private_key is None:
            return "Tạo chữ ký số", f"H1 = {digest}; không ký (đã tắt chữ ký số)."
        return "Tạo chữ ký số", f"H1 = {digest}; đã ký plaintext bằng RSA-PSS/SHA-256."

    def _compress_content(self) -> tuple[str, str]:
        _, packed = self._pack()
        _, compressed = self._compress()
        return "Nén dữ liệu", f"Ghép plaintext + chữ ký: {packed}; nén zlib: {compressed}."

    def _encrypt_hybrid(self) -> tuple[str, str]:
        if self.recipient_public_key is None:
            _, payload = self._plain_payload()
            return "Mã hóa lai", f"Bỏ qua: không chọn mã hóa. Payload {payload}."
        _, encrypted = self._encrypt()
        _, wrapped = self._wrap_session_key()
        _, payload = self._encrypted_payload()
        return (
            "Mã hóa lai",
            f"AES-256-GCM: {encrypted}. Bọc khóa phiên bằng RSA-OAEP: {len(wrapped) // 2} byte. {payload}.",
        )


def create_message(
    message: str,
    recipient_public_key: rsa.RSAPublicKey | None = None,
    signing_private_key: rsa.RSAPrivateKey | None = None,
    signer_fingerprint: str | None = None,
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Tạo gói tin tùy chọn ký và mã hóa, cùng thông tin các bước xử lý."""
    session = MessageCreationSession(
        message,
        recipient_public_key,
        signing_private_key,
        signer_fingerprint,
    )
    while not session.done:
        session.advance()
    return session.envelope, session.steps


def decrypt_message(
    envelope: dict[str, Any],
    recipient_private_key: rsa.RSAPrivateKey | None = None,
    steps: list[tuple[str, str]] | None = None,
) -> tuple[str, dict[str, str] | None]:
    """Giải mã gói tin, trả về nội dung và thông tin chữ ký (chưa xác minh)."""
    if not isinstance(envelope, dict) or envelope.get("version") != 1:
        raise CryptoError("Phiên bản hoặc cấu trúc gói tin không được hỗ trợ.")
    try:
        try:
            payload = bytes.fromhex(envelope["payload"])
        except (ValueError, KeyError, TypeError) as exc:
            raise CryptoError("Payload không đúng định dạng hex hoặc bị thiếu.") from exc
        if steps is not None:
            steps.append(("Đọc payload", f"Đọc được {len(payload)} byte payload dạng hex."))
        if envelope.get("encrypted"):
            if recipient_private_key is None:
                raise CryptoError("Gói tin đã mã hóa; cần khóa riêng của người nhận.")
            if envelope.get("recipient_fingerprint") != fingerprint(recipient_private_key.public_key()):
                raise CryptoError("Gói tin không được gửi cho khóa riêng này.")
            if steps is not None:
                steps.append(
                    (
                        "Đối chiếu khóa người nhận",
                        f"Fingerprint khớp: {envelope['recipient_fingerprint']}",
                    )
                )
            try:
                encrypted_session_key = bytes.fromhex(envelope["encrypted_session_key"])
                nonce = bytes.fromhex(envelope["nonce"])
            except (ValueError, KeyError, TypeError) as exc:
                raise CryptoError("Metadata khóa phiên RSA-OAEP hoặc nonce không hợp lệ.") from exc
            try:
                session_key = recipient_private_key.decrypt(
                    encrypted_session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except (ValueError, TypeError) as exc:
                raise CryptoError("Không mở được khóa phiên RSA-OAEP: khóa hoặc dữ liệu không hợp lệ.") from exc
            if steps is not None:
                steps.append(
                    (
                        "Mở khóa phiên RSA-OAEP",
                        "Khôi phục khóa AES-256 bằng khóa riêng người nhận; giá trị khóa được ẩn.",
                    )
                )
            payload = AESGCM(session_key).decrypt(nonce, payload, None)
            if steps is not None:
                steps.append(
                    (
                        "Giải mã và kiểm tra AES-256-GCM",
                        f"Giải mã thành công; thẻ xác thực hợp lệ, {len(payload)} byte dữ liệu nén.",
                    )
                )
        elif envelope.get("compression") != "zlib":
            raise CryptoError("Thuật toán nén trong gói tin không được hỗ trợ.")
        elif steps is not None:
            steps.append(("Kiểm tra mã hóa", "Gói tin không mã hóa; bỏ qua AES và RSA-OAEP."))
        compressed_size = len(payload)
        try:
            payload = zlib.decompress(payload)
        except zlib.error as exc:
            raise CryptoError("Giải nén zlib thất bại: dữ liệu nén đã hỏng hoặc bị sửa.") from exc
        if steps is not None:
            steps.append(("Giải nén zlib", f"{compressed_size} byte → {len(payload)} byte"))
        try:
            content = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CryptoError("Cấu trúc plaintext JSON không hợp lệ hoặc đã bị sửa.") from exc
        message = content["message"]
        signature = content.get("signature")
        if not isinstance(message, str):
            raise CryptoError("Nội dung gói tin không phải văn bản.")
        if signature is not None and not isinstance(signature, dict):
            raise CryptoError("Chữ ký trong gói tin không đúng định dạng.")
        if steps is not None:
            steps.append(
                (
                    "Tách nội dung và chữ ký",
                    "Đã lấy plaintext" + (" cùng chữ ký số." if signature is not None else "; gói tin không có chữ ký."),
                )
            )
        return message, signature
    except CryptoError:
        raise
    except InvalidTag as exc:
        raise CryptoError("Xác thực AES-GCM thất bại: payload đã bị sửa hoặc hỏng.") from exc
    except (ValueError, KeyError, TypeError, zlib.error, json.JSONDecodeError) as exc:
        raise CryptoError("Không thể giải mã gói tin: dữ liệu hỏng, khóa sai hoặc gói đã bị sửa.") from exc


def verify_signature(
    message: str,
    signature: dict[str, str],
    public_key: rsa.RSAPublicKey,
) -> bool:
    """Xác minh chữ ký RSA-PSS; trả False nếu chữ ký hoặc nội dung bị sửa."""
    if signature.get("algorithm") != "RSA-PSS-SHA256":
        return False
    try:
        public_key.verify(
            bytes.fromhex(signature["value"]),
            message.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True
