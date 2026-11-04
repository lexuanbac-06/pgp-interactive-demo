"""Menu CLI tương tác cho bản mô phỏng PGP."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Callable

from . import armor, attack, crypto
from .crypto import CryptoError
from .keys import KeyringError, PublicIdentity
from .users import User, Users


def read_armored_block(label: str) -> str:
    """Đọc một khối armor nhiều dòng cho đến dòng END tương ứng."""
    end_marker = f"-----END PGP {label}-----"
    print(f"Dán khối ASCII armor {label}; kết thúc tại dòng {end_marker}")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError as exc:
            raise ValueError("Kết thúc nhập trước khi nhận đủ khối armor.") from exc
        lines.append(line)
        if line.strip() == end_marker:
            return "\n".join(lines)


def _choose_user(users: Users, prompt: str = "Chọn người dùng") -> User:
    people = users.list()
    print(f"\n{prompt}:")
    for index, user in enumerate(people, 1):
        print(f"  {index}. {user.name}")
    while True:
        choice = input("Lựa chọn: ").strip()
        try:
            index = int(choice)
            if 1 <= index <= len(people):
                return people[index - 1]
        except ValueError:
            pass
        print("Lựa chọn không hợp lệ; hãy nhập số trong danh sách.")


def _yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    value = input(prompt + suffix).strip().casefold()
    if not value:
        return default
    return value in {"y", "yes", "c", "co", "có"}


def _all_recipients(users: Users, sender: User) -> list[tuple[str, PublicIdentity]]:
    choices: list[tuple[str, PublicIdentity]] = []
    for user in users.list():
        if user.user_id == sender.user_id:
            continue
        identity = users.keyring(user).own_identity()
        if identity:
            choices.append((user.name, identity))
    for contact in users.keyring(sender).list_contacts():
        if all(contact.fingerprint != identity.fingerprint for _, identity in choices):
            choices.append((contact.name + " (khóa đã import)", contact))
    return choices


def _compose(users: Users, sender: User) -> None:
    keyring = users.keyring(sender)
    message = input("\nNội dung tin nhắn: ")
    if not message.strip():
        print("Nội dung không được để trống.")
        return

    encrypt = _yes_no("Mã hóa cho người nhận?")
    recipient: PublicIdentity | None = None
    if encrypt:
        recipients = _all_recipients(users, sender)
        if not recipients:
            print("Chưa có khóa công khai người nhận. Hãy tạo khóa cho Bob hoặc import khóa.")
            return
        print("Người nhận:")
        for index, (name, identity) in enumerate(recipients, 1):
            print(f"  {index}. {name} — {identity.fingerprint}")
        try:
            choice = int(input("Lựa chọn: "))
            if not 1 <= choice <= len(recipients):
                raise ValueError
        except ValueError:
            print("Lựa chọn người nhận không hợp lệ.")
            return
        recipient = recipients[choice - 1][1]

    sign = _yes_no("Ký tin nhắn?")
    private_key = None
    signer_fingerprint = None
    if sign:
        identity = keyring.own_identity()
        if not identity or not keyring.has_private_key:
            print("Người gửi chưa có cặp khóa. Hãy tạo khóa trước.")
            return
        private_key = keyring.load_private(getpass.getpass("Passphrase của người ký: "))
        signer_fingerprint = identity.fingerprint

    envelope, steps = crypto.create_message(
        message,
        recipient.public_key if recipient else None,
        private_key,
        signer_fingerprint,
    )
    print("\nCác bước bên trong:")
    for label, detail in steps:
        print(f"  {label}: {detail}")
    print("\nGói tin ASCII armor:\n")
    print(armor.encode("MESSAGE", envelope))


def _receive(users: Users, receiver: User) -> None:
    armored = read_armored_block("MESSAGE")
    envelope = armor.decode(armored, "MESSAGE")
    recipient_private = None
    if envelope.get("encrypted"):
        recipient_private = users.keyring(receiver).load_private(
            getpass.getpass(f"Passphrase khóa riêng của {receiver.name}: ")
        )
    message, signature = crypto.decrypt_message(envelope, recipient_private)
    print(f"\nNội dung:\n{message}")
    if signature is None:
        print("\nChữ ký: tin nhắn không có chữ ký.")
        return
    if not isinstance(signature, dict) or not isinstance(signature.get("fingerprint"), str):
        print("\nChữ ký: không rõ người ký (thông tin fingerprint không hợp lệ).")
        return
    signer = users.keyring(receiver).find_public(signature["fingerprint"])
    if signer is None:
        print(
            "\nChữ ký: không rõ người ký. "
            f"Chưa import khóa có fingerprint {signature['fingerprint']}."
        )
    elif crypto.verify_signature(message, signature, signer.public_key):
        print(f"\nChữ ký: HỢP LỆ — {signer.name} ({signer.fingerprint}).")
    else:
        print("\nChữ ký: KHÔNG HỢP LỆ — nội dung/chữ ký có thể đã bị sửa.")


def _show_keyring(users: Users, user: User) -> None:
    keyring = users.keyring(user)
    own = keyring.own_identity()
    print(f"\nKeyring của {user.name}:")
    if own:
        print(f"  Khóa của tôi: {own.fingerprint}")
    else:
        print("  Chưa tạo khóa riêng.")
    contacts = keyring.list_contacts()
    if contacts:
        print("  Khóa công khai đã import:")
        for contact in contacts:
            print(f"    {contact.name}: {contact.fingerprint}")
    else:
        print("  Chưa import khóa công khai nào.")


def _create_key(users: Users, user: User) -> None:
    size_text = input("RSA 2048 hay 4096 bit? [2048]: ").strip() or "2048"
    try:
        bits = int(size_text)
    except ValueError as exc:
        raise KeyringError("Kích thước khóa phải là 2048 hoặc 4096.") from exc
    passphrase = getpass.getpass("Passphrase mới (ít nhất 8 ký tự): ")
    confirmation = getpass.getpass("Nhập lại passphrase: ")
    if passphrase != confirmation:
        raise KeyringError("Hai passphrase không trùng khớp.")
    fingerprint = users.keyring(user).generate(passphrase, bits)
    print(f"Đã tạo khóa RSA {bits} bit. Fingerprint: {fingerprint}")


def _export_key(users: Users, user: User) -> None:
    block = users.keyring(user).export_public()
    destination = input("Lưu vào tệp (Enter để in ra terminal): ").strip()
    if destination:
        Path(destination).write_text(block + "\n", encoding="utf-8")
        print(f"Đã export khóa công khai vào {destination}.")
    else:
        print("\nSao chép toàn bộ khối sau để chia sẻ:\n")
        print(block)


def _import_key(users: Users, user: User) -> None:
    block = read_armored_block("PUBLIC KEY")
    identity = users.keyring(user).import_public(block)
    print(f"Đã import khóa của {identity.name}. Fingerprint: {identity.fingerprint}")


def _attack_menu(users: Users, user: User) -> None:
    print("\nChế độ tấn công:")
    print("  1. Sửa một byte payload")
    print("  2. Thử giải mã gói tin bằng Eve")
    choice = input("Lựa chọn: ").strip()
    if choice == "1":
        block = read_armored_block("MESSAGE")
        print("\nGói tin đã sửa:\n")
        print(attack.tamper_package(block))
    elif choice == "2":
        eve = next((person for person in users.list() if person.name.casefold() == "eve"), None)
        if eve is None:
            print("Không tìm thấy người dùng tên Eve.")
            return
        block = read_armored_block("MESSAGE")
        passphrase = getpass.getpass("Passphrase khóa riêng của Eve: ")
        try:
            message, _ = attack.try_as_eve(block, users.keyring(eve), passphrase)
        except (CryptoError, KeyringError) as exc:
            print(f"Eve không giải mã được: {exc}")
        else:
            print(f"Eve giải mã được nội dung: {message}")
    else:
        print("Lựa chọn không hợp lệ.")


def run(data_directory: str | Path | None = None) -> None:
    default_data = Path(__file__).resolve().parent.parent / "data"
    users = Users(data_directory or default_data)
    actions: dict[str, Callable[[Users, User], None]] = {
        "1": _show_keyring,
        "2": _create_key,
        "3": _export_key,
        "4": _import_key,
        "5": _compose,
        "6": _receive,
        "7": _attack_menu,
    }
    while True:
        print("\n=== PGP Demo — mô phỏng học tập ===")
        print("  1. Chọn người dùng")
        print("  2. Thêm người dùng")
        print("  0. Thoát")
        choice = input("Lựa chọn: ").strip()
        if choice == "0":
            return
        if choice == "2":
            name = input("Tên người dùng mới: ")
            try:
                user = users.add(name)
                print(f"Đã thêm {user.name}.")
            except ValueError as exc:
                print(f"Lỗi: {exc}")
            continue
        if choice != "1":
            print("Lựa chọn không hợp lệ.")
            continue

        try:
            active = _choose_user(users)
            while True:
                print(f"\n--- {active.name} ---")
                print("  1. Xem keyring")
                print("  2. Tạo khóa")
                print("  3. Export khóa công khai")
                print("  4. Import khóa công khai")
                print("  5. Soạn / ký / mã hóa tin")
                print("  6. Giải mã / xác minh tin")
                print("  7. Chế độ tấn công")
                print("  0. Quay lại")
                action = input("Lựa chọn: ").strip()
                if action == "0":
                    break
                handler = actions.get(action)
                if handler is None:
                    print("Lựa chọn không hợp lệ.")
                    continue
                try:
                    handler(users, active)
                except (ValueError, OSError) as exc:
                    print(f"Lỗi: {exc}")
        except (ValueError, OSError) as exc:
            print(f"Lỗi: {exc}")


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Interactive educational PGP demo.")
    parser.add_argument("--data-dir", type=Path, help="Thư mục lưu người dùng và keyring.")
    args = parser.parse_args()
    try:
        run(args.data_dir)
    except (KeyboardInterrupt, EOFError):
        print("\nĐã thoát.")
        sys.exit(0)


if __name__ == "__main__":
    main()
