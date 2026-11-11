from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pgp_demo import armor, attack, crypto
from pgp_demo.crypto import CryptoError
from pgp_demo.keys import Keyring
from pgp_demo.users import Users


@pytest.fixture
def key_pair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_hybrid_encrypt_sign_decrypt_and_verify(key_pair: rsa.RSAPrivateKey) -> None:
    fingerprint = "ABCD 1234"
    envelope, steps = crypto.create_message(
        "Xin chào Bob 🌿",
        key_pair.public_key(),
        key_pair,
        fingerprint,
    )
    armored = armor.encode("MESSAGE", envelope)
    decoded_envelope = armor.decode(armored, "MESSAGE")

    message, signature = crypto.decrypt_message(decoded_envelope, key_pair)

    assert message == "Xin chào Bob 🌿"
    assert signature is not None
    assert signature["fingerprint"] == fingerprint
    assert crypto.verify_signature(message, signature, key_pair.public_key())
    assert any(label == "Sinh khóa phiên" for label, _ in steps)
    assert "BEGIN PGP MESSAGE" in armored


def test_modified_payload_fails_authentication(key_pair: rsa.RSAPrivateKey) -> None:
    envelope, _ = crypto.create_message("Tin bí mật", key_pair.public_key())
    modified = armor.decode(attack.tamper_package(armor.encode("MESSAGE", envelope)), "MESSAGE")

    with pytest.raises(CryptoError, match="AES-GCM"):
        crypto.decrypt_message(modified, key_pair)


def test_signed_plaintext_detects_modified_message(key_pair: rsa.RSAPrivateKey) -> None:
    envelope, _ = crypto.create_message("Nội dung ban đầu", signing_private_key=key_pair, signer_fingerprint="FP")
    message, signature = crypto.decrypt_message(envelope)

    assert signature is not None
    assert crypto.verify_signature(message, signature, key_pair.public_key())
    assert not crypto.verify_signature(message + " bị sửa", signature, key_pair.public_key())


def test_wrong_private_key_cannot_decrypt() -> None:
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eve = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    envelope, _ = crypto.create_message("Chỉ Bob đọc được", recipient.public_key())

    with pytest.raises(CryptoError):
        crypto.decrypt_message(envelope, eve)


def test_keyring_export_import_and_passphrase(tmp_path) -> None:
    alice = Keyring(tmp_path / "alice", "Alice")
    bob = Keyring(tmp_path / "bob", "Bob")
    fingerprint = alice.generate("alice-passphrase", 2048)
    imported = bob.import_public(alice.export_public())

    assert imported.fingerprint == fingerprint
    assert bob.find_public(fingerprint) is not None
    with pytest.raises(ValueError, match="Passphrase sai"):
        alice.load_private("wrong-passphrase")


def test_delete_user_removes_keyring_and_preserves_last_identity(tmp_path) -> None:
    users = Users(tmp_path)
    user = users.add("Temporary")
    keyring = users.keyring(user)
    keyring.generate("temporary-passphrase", 2048)
    keyring_directory = users.users_directory / user.user_id

    deleted = users.delete(user.user_id)

    assert deleted == user
    assert all(item.user_id != user.user_id for item in users.list())
    assert not keyring_directory.exists()
    with pytest.raises(ValueError, match="Không tìm thấy"):
        users.delete(user.user_id)

    remaining = users.list()
    for item in remaining[:-1]:
        users.delete(item.user_id)
    with pytest.raises(ValueError, match="cuối cùng"):
        users.delete(users.list()[0].user_id)
