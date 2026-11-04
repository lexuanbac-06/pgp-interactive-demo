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


def create_message(
    message: str,
    recipient_public_key: rsa.RSAPublicKey | None = None,
    signing_private_key: rsa.RSAPrivateKey | None = None,
    signer_fingerprint: str | None = None,
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Tạo gói tin tùy chọn ký và mã hóa, cùng thông tin các bước xử lý."""
    if not isinstance(message, str) or not message:
        raise CryptoError("Nội dung tin nhắn không được để trống.")
    if (signing_private_key is None) != (signer_fingerprint is None):
        raise CryptoError("Cần có cả khóa ký lẫn fingerprint người ký.")

    message_bytes = message.encode("utf-8")
    digest = hashlib.sha256(message_bytes).hexdigest()
    signature: dict[str, str] | None = None
    steps = [("Hash SHA-256", digest)]
    if signing_private_key is not None:
        signature_bytes = signing_private_key.sign(
            message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        signature = {
            "fingerprint": signer_fingerprint or "",
            "algorithm": "RSA-PSS-SHA256",
            "value": signature_bytes.hex(),
        }
        steps.append(("Chữ ký RSA-PSS", signature_bytes.hex()))
    else:
        steps.append(("Chữ ký", "Không ký tin nhắn"))

    content = json.dumps(
        {"message": message, "signature": signature},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    compressed = zlib.compress(content)
    steps.append(("Nén zlib", f"{len(content)} byte → {len(compressed)} byte"))

    envelope: dict[str, Any] = {
        "version": 1,
        "encrypted": recipient_public_key is not None,
        "compression": "zlib",
        "payload": "",
        "recipient_fingerprint": None,
        "encrypted_session_key": None,
        "nonce": None,
    }

    if recipient_public_key is None:
        envelope["payload"] = compressed.hex()
        steps.extend(
            [
                ("Khóa phiên AES", "Không mã hóa"),
                ("Khóa phiên mã hóa RSA", "Không mã hóa"),
                ("Payload", f"{len(compressed)} byte (chưa mã hóa)"),
            ]
        )
        return envelope, steps

    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, compressed, None)
    encrypted_session_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    envelope.update(
        {
            "payload": ciphertext.hex(),
            "recipient_fingerprint": fingerprint(recipient_public_key),
            "encrypted_session_key": encrypted_session_key.hex(),
            "nonce": nonce.hex(),
        }
    )
    steps.extend(
        [
            ("Khóa phiên AES-256", session_key.hex()),
            ("Khóa phiên bọc bằng RSA-OAEP", encrypted_session_key.hex()),
            ("Payload AES-GCM", f"{len(ciphertext)} byte (đã mã hóa)"),
        ]
    )
    return envelope, steps


def decrypt_message(
    envelope: dict[str, Any],
    recipient_private_key: rsa.RSAPrivateKey | None = None,
) -> tuple[str, dict[str, str] | None]:
    """Giải mã gói tin, trả về nội dung và thông tin chữ ký (chưa xác minh)."""
    if not isinstance(envelope, dict) or envelope.get("version") != 1:
        raise CryptoError("Phiên bản hoặc cấu trúc gói tin không được hỗ trợ.")
    try:
        payload = bytes.fromhex(envelope["payload"])
        if envelope.get("encrypted"):
            if recipient_private_key is None:
                raise CryptoError("Gói tin đã mã hóa; cần khóa riêng của người nhận.")
            if envelope.get("recipient_fingerprint") != fingerprint(recipient_private_key.public_key()):
                raise CryptoError("Gói tin không được gửi cho khóa riêng này.")
            encrypted_session_key = bytes.fromhex(envelope["encrypted_session_key"])
            nonce = bytes.fromhex(envelope["nonce"])
            session_key = recipient_private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            payload = AESGCM(session_key).decrypt(nonce, payload, None)
        elif envelope.get("compression") != "zlib":
            raise CryptoError("Thuật toán nén trong gói tin không được hỗ trợ.")
        content = json.loads(zlib.decompress(payload).decode("utf-8"))
        message = content["message"]
        signature = content.get("signature")
        if not isinstance(message, str):
            raise CryptoError("Nội dung gói tin không phải văn bản.")
        if signature is not None and not isinstance(signature, dict):
            raise CryptoError("Chữ ký trong gói tin không đúng định dạng.")
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
