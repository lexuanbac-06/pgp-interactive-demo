"""Quản lý danh sách người dùng và keyring riêng của từng người."""

from __future__ import annotations

import json
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from .keys import Keyring


@dataclass(frozen=True)
class User:
    user_id: str
    name: str


class Users:
    def __init__(self, data_directory: str | Path) -> None:
        self.data_directory = Path(data_directory)
        self.users_directory = self.data_directory / "users"
        self.registry_path = self.data_directory / "users.json"
        self.data_directory.mkdir(parents=True, exist_ok=True)
        if not self.registry_path.exists():
            for name in ("Alice", "Bob", "Eve"):
                self.add(name)

    def list(self) -> list[User]:
        try:
            entries = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Không đọc được danh sách người dùng.") from exc
        if not isinstance(entries, list):
            raise ValueError("Danh sách người dùng không đúng định dạng.")
        return [User(item["id"], item["name"]) for item in entries]

    def add(self, name: str) -> User:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Tên người dùng không được để trống.")
        current = self.list() if self.registry_path.exists() else []
        if any(user.name.casefold() == clean_name.casefold() for user in current):
            raise ValueError("Tên người dùng đã tồn tại.")
        user = User(uuid.uuid4().hex, clean_name)
        entries = [{"id": item.user_id, "name": item.name} for item in current]
        entries.append({"id": user.user_id, "name": user.name})
        self._save(entries)
        return user

    def keyring(self, user: User) -> Keyring:
        return Keyring(self.users_directory / user.user_id, user.name)

    def get(self, user_id: str) -> User:
        for user in self.list():
            if user.user_id == user_id:
                return user
        raise ValueError("Không tìm thấy người dùng đã chọn.")

    def _save(self, entries: list[dict[str, str]]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.registry_path.parent,
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(entries, handle, ensure_ascii=False, indent=2)
                handle.flush()
            temporary.replace(self.registry_path)
        except OSError:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise
