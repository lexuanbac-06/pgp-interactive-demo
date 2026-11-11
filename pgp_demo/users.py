"""Quản lý danh sách người dùng và keyring riêng của từng người."""

from __future__ import annotations

import errno
import json
import shutil
import tempfile
import threading
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
        self._mutation_lock = threading.Lock()
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
        with self._mutation_lock:
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

    def delete(self, user_id: str) -> User:
        with self._mutation_lock:
            current = self.list()
            user = next((item for item in current if item.user_id == user_id), None)
            if user is None:
                raise ValueError("Không tìm thấy người dùng đã chọn.")
            if len(current) == 1:
                raise ValueError("Không thể xóa danh tính cuối cùng.")

            self.users_directory.mkdir(parents=True, exist_ok=True)
            user_directory = self.users_directory / user.user_id
            if user_directory.is_symlink():
                raise ValueError("Không thể xóa keyring liên kết ngoài thư mục người dùng.")
            users_root = self.users_directory.resolve()
            resolved_directory = user_directory.resolve()
            try:
                resolved_directory.relative_to(users_root)
            except ValueError as exc:
                raise ValueError("Thư mục keyring không hợp lệ.") from exc

            staged_directory = self.users_directory / f".deleted-{uuid.uuid4().hex}"
            mounted_directory = False
            if user_directory.exists():
                try:
                    user_directory.replace(staged_directory)
                except OSError as exc:
                    if exc.errno != errno.EXDEV:
                        raise
                    self._clear_directory_contents(user_directory)
                    mounted_directory = True
            try:
                remaining = [
                    {"id": item.user_id, "name": item.name}
                    for item in current
                    if item.user_id != user_id
                ]
                self._save(remaining)
            except OSError:
                if staged_directory.exists():
                    staged_directory.replace(user_directory)
                raise

            if staged_directory.exists():
                try:
                    shutil.rmtree(staged_directory, ignore_errors=False)
                except OSError as exc:
                    raise OSError(
                        f"Đã xóa danh tính nhưng không thể xóa toàn bộ dữ liệu keyring: {exc}"
                    ) from exc
            if mounted_directory and self._directory_has_data(user_directory):
                raise OSError("Đã xóa danh tính nhưng thư mục keyring vẫn còn dữ liệu.")
            return user

    @classmethod
    def _clear_directory_contents(cls, directory: Path) -> None:
        for child in directory.iterdir():
            if child.is_symlink() or not child.is_dir():
                child.unlink()
                continue
            try:
                shutil.rmtree(child)
            except OSError as exc:
                if exc.errno not in {errno.EXDEV, errno.EBUSY}:
                    raise
                cls._clear_directory_contents(child)
                try:
                    child.rmdir()
                except OSError as remove_error:
                    if remove_error.errno not in {errno.EXDEV, errno.EBUSY}:
                        raise

    @classmethod
    def _directory_has_data(cls, directory: Path) -> bool:
        for child in directory.iterdir():
            if child.is_symlink() or not child.is_dir():
                return True
            if cls._directory_has_data(child):
                return True
        return False

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
