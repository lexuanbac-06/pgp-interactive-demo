"""Các thao tác thử nghiệm tấn công trên gói tin mô phỏng."""

from __future__ import annotations

from typing import Any

from . import armor
from .crypto import CryptoError, decrypt_message
from .keys import Keyring


def tamper_package(armored_message: str) -> str:
    """Thay đổi một byte payload và đóng gói lại khối armor."""
    envelope = armor.decode(armored_message, "MESSAGE")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
        raise CryptoError("Gói tin không có payload hợp lệ để sửa.")
    try:
        payload = bytearray.fromhex(envelope["payload"])
    except ValueError as exc:
        raise CryptoError("Payload không phải dữ liệu hex hợp lệ.") from exc
    if not payload:
        raise CryptoError("Payload rỗng, không thể sửa.")
    payload[len(payload) // 2] ^= 1
    envelope["payload"] = payload.hex()
    return armor.encode("MESSAGE", envelope)


def try_as_eve(
    armored_message: str,
    eve_keyring: Keyring,
    passphrase: str,
) -> tuple[str, dict[str, Any] | None]:
    """Thử giải mã gói tin với khóa riêng của Eve."""
    envelope = armor.decode(armored_message, "MESSAGE")
    private_key = eve_keyring.load_private(passphrase)
    return decrypt_message(envelope, private_key)
