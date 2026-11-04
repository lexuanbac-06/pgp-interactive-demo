"""Đóng gói dữ liệu thành ASCII armor của bản mô phỏng."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any


class ArmorError(ValueError):
    """Khối ASCII armor sai định dạng hoặc không hợp lệ."""


def encode(label: str, data: Any) -> str:
    """Mã hóa JSON thành một khối ASCII armor."""
    if not re.fullmatch(r"[A-Z ]+", label):
        raise ArmorError("Nhãn armor chỉ được chứa chữ hoa và dấu cách.")
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    lines = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return f"-----BEGIN PGP {label}-----\nVersion: PGP Demo (educational simulation)\n\n{lines}\n-----END PGP {label}-----"


def decode(armored: str, expected_label: str) -> Any:
    """Giải mã một khối armor và trả về đối tượng JSON."""
    if not isinstance(armored, str):
        raise ArmorError("Khối armor phải là văn bản.")
    if not re.fullmatch(r"[A-Z ]+", expected_label):
        raise ArmorError("Nhãn armor không hợp lệ.")

    begin = f"-----BEGIN PGP {expected_label}-----"
    end = f"-----END PGP {expected_label}-----"
    lines = armored.strip().splitlines()
    try:
        start = lines.index(begin)
        finish = lines.index(end, start + 1)
    except ValueError as exc:
        raise ArmorError(f"Không tìm thấy khối {expected_label} có BEGIN/END phù hợp.") from exc

    body_lines = lines[start + 1 : finish]
    separator = next((index for index, line in enumerate(body_lines) if not line.strip()), None)
    if separator is None:
        raise ArmorError("Khối armor thiếu dòng trống ngăn cách header và dữ liệu.")

    encoded = "".join(line.strip() for line in body_lines[separator + 1 :])
    if not encoded:
        raise ArmorError("Khối armor không có dữ liệu.")
    try:
        raw = base64.b64decode(encoded, validate=True)
        return json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArmorError("Dữ liệu Base64/JSON trong khối armor không hợp lệ hoặc đã bị sửa.") from exc
