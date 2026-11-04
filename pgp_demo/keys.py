"""Sinh, lưu, nạp và quản lý khóa RSA cùng keyring."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import armor


class KeyringError(ValueError):
    """Lỗi thao tác với khóa hoặc keyring."""


@dataclass(frozen=True)
class PublicIdentity:
    name: str
    fingerprint: str
    public_key: rsa.RSAPublicKey


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Fingerprint SHA-256 của khóa RSA công khai, hiển thị theo nhóm 4 hex."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return " ".join(digest[index : index + 4] for index in range(0, len(digest), 4))


def _public_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _load_public_pem(value: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(value.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise KeyringError("Khóa công khai PEM không hợp lệ.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyringError("Chỉ hỗ trợ khóa RSA.")
    return key


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary_path = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


class Keyring:
    """Keyring của một người dùng, lưu cặp khóa riêng và khóa công khai đã import."""

    def __init__(self, directory: str | Path, name: str) -> None:
        self.directory = Path(directory)
        self.name = name
        self.private_path = self.directory / "private_key.pem"
        self.public_path = self.directory / "public_key.pem"
        self.contacts_path = self.directory / "contacts.json"

    @property
    def has_private_key(self) -> bool:
        return self.private_path.is_file()

    def generate(self, passphrase: str, bits: int = 2048) -> str:
        if len(passphrase) < 8:
            raise KeyringError("Passphrase phải có ít nhất 8 ký tự.")
        if bits not in (2048, 4096):
            raise KeyringError("Kích thước khóa chỉ được là RSA 2048 hoặc 4096 bit.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        public_pem = _public_pem(private_key.public_key()).encode("ascii")
        _atomic_write(self.private_path, private_pem)
        _atomic_write(self.public_path, public_pem)
        return fingerprint(private_key.public_key())

    def load_private(self, passphrase: str) -> rsa.RSAPrivateKey:
        try:
            key = serialization.load_pem_private_key(
                self.private_path.read_bytes(),
                password=passphrase.encode("utf-8"),
            )
        except FileNotFoundError as exc:
            raise KeyringError(f"{self.name} chưa tạo khóa riêng.") from exc
        except (ValueError, TypeError) as exc:
            raise KeyringError("Passphrase sai hoặc tệp khóa riêng không hợp lệ.") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeyringError("Tệp khóa không chứa khóa riêng RSA.")
        return key

    def own_identity(self) -> PublicIdentity | None:
        if not self.public_path.is_file():
            return None
        key = _load_public_pem(self.public_path.read_text(encoding="ascii"))
        return PublicIdentity(self.name, fingerprint(key), key)

    def export_public(self) -> str:
        identity = self.own_identity()
        if identity is None:
            raise KeyringError(f"{self.name} chưa có khóa công khai để export.")
        return armor.encode(
            "PUBLIC KEY",
            {
                "version": 1,
                "name": identity.name,
                "fingerprint": identity.fingerprint,
                "public_key": _public_pem(identity.public_key),
            },
        )

    def import_public(self, armored: str) -> PublicIdentity:
        data = armor.decode(armored, "PUBLIC KEY")
        if not isinstance(data, dict) or data.get("version") != 1:
            raise KeyringError("Khối khóa không đúng phiên bản hoặc cấu trúc.")
        if not isinstance(data.get("name"), str) or not isinstance(data.get("public_key"), str):
            raise KeyringError("Khối khóa thiếu tên hoặc khóa công khai.")
        public_key = _load_public_pem(data["public_key"])
        actual_fingerprint = fingerprint(public_key)
        if data.get("fingerprint") != actual_fingerprint:
            raise KeyringError("Fingerprint không khớp nội dung khóa; khối khóa có thể đã bị sửa.")

        contacts = self._read_contacts()
        if actual_fingerprint == (self.own_identity().fingerprint if self.own_identity() else None):
            raise KeyringError("Khóa này đã là khóa của người dùng.")
        if actual_fingerprint in contacts:
            raise KeyringError("Khóa này đã có trong keyring.")
        contacts[actual_fingerprint] = {
            "name": data["name"],
            "public_key": data["public_key"],
        }
        self._write_contacts(contacts)
        return PublicIdentity(data["name"], actual_fingerprint, public_key)

    def list_contacts(self) -> list[PublicIdentity]:
        contacts = self._read_contacts()
        return [
            PublicIdentity(item["name"], fp, _load_public_pem(item["public_key"]))
            for fp, item in contacts.items()
        ]

    def find_public(self, wanted_fingerprint: str) -> PublicIdentity | None:
        own = self.own_identity()
        if own and own.fingerprint == wanted_fingerprint:
            return own
        for contact in self.list_contacts():
            if contact.fingerprint == wanted_fingerprint:
                return contact
        return None

    def _read_contacts(self) -> dict[str, dict[str, Any]]:
        if not self.contacts_path.exists():
            return {}
        try:
            value = json.loads(self.contacts_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyringError("Không đọc được contacts.json trong keyring.") from exc
        if not isinstance(value, dict):
            raise KeyringError("Định dạng contacts.json không hợp lệ.")
        return value

    def _write_contacts(self, contacts: dict[str, dict[str, Any]]) -> None:
        encoded = json.dumps(contacts, ensure_ascii=False, indent=2).encode("utf-8")
        _atomic_write(self.contacts_path, encoded)
