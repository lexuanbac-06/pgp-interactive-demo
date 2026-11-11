from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
import zlib

import pytest

from pgp_demo import armor
from pgp_demo.web import create_server


@pytest.fixture
def web_server(tmp_path):
    server = create_server(tmp_path, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_json(base_url: str, path: str, payload: dict | None = None) -> dict:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Content-Type": "application/json"} if payload is not None else {},
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def delete_json(base_url: str, path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="DELETE",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def open_stepwise(base_url: str, payload: dict) -> dict:
    current = request_json(base_url, "/api/messages/open", payload)
    return finish_open(base_url, current)


def finish_open(base_url: str, current: dict) -> dict:
    steps = [current["step"]]
    while not current["done"]:
        current = request_json(
            base_url,
            "/api/messages/open/next",
            {"session_id": current["session_id"]},
        )
        steps.append(current["step"])
    return {"steps": steps, **(current.get("result") or {})}


def create_stepwise(base_url: str, payload: dict) -> dict:
    current = request_json(base_url, "/api/messages/create", payload)
    return finish_create(base_url, current)


def finish_create(base_url: str, current: dict) -> dict:
    steps = [current["step"]]
    while not current["done"]:
        current = request_json(
            base_url,
            "/api/messages/create/next",
            {"session_id": current["session_id"]},
        )
        steps.append(current["step"])
    return {"steps": steps, **(current.get("result") or {})}


def test_web_ui_hybrid_signed_message_flow(web_server: str) -> None:
    with urllib.request.urlopen(web_server + "/") as response:
        page = response.read().decode("utf-8")
        assert response.headers["Content-Type"].startswith("text/html")
    assert 'id="root"' in page
    assets = re.findall(r'(?:src|href)="([^"]+)"', page)
    asset_paths = [path for path in assets if path.startswith("/assets/")]
    assert len(asset_paths) >= 2
    for asset_path in asset_paths:
        with urllib.request.urlopen(web_server + asset_path) as response:
            assert response.status == 200
            assert response.read()
    with pytest.raises(urllib.error.HTTPError) as traversal:
        urllib.request.urlopen(web_server + "/assets/%2e%2e/%2e%2e/README.md")
    assert traversal.value.code == 404

    users = request_json(web_server, "/api/state")["users"]
    alice = next(user for user in users if user["name"] == "Alice")
    bob = next(user for user in users if user["name"] == "Bob")
    eve = next(user for user in users if user["name"] == "Eve")

    alice_key = request_json(
        web_server,
        "/api/keys/generate",
        {"user_id": alice["id"], "passphrase": "alice-passphrase", "bits": 2048},
    )
    bob_key = request_json(
        web_server,
        "/api/keys/generate",
        {"user_id": bob["id"], "passphrase": "bob-passphrase", "bits": 2048},
    )
    request_json(
        web_server,
        "/api/keys/generate",
        {"user_id": eve["id"], "passphrase": "eve-passphrase", "bits": 2048},
    )
    public_key = request_json(
        web_server, "/api/keys/export", {"user_id": alice["id"]}
    )["armored"]
    request_json(
        web_server,
        "/api/keys/import",
        {"user_id": bob["id"], "armored": public_key},
    )

    create_start = request_json(
        web_server,
        "/api/messages/create",
        {
            "sender_id": alice["id"],
            "message": "Xin chào Bob từ giao diện web.",
            "encrypt": True,
            "recipient_fingerprint": bob_key["fingerprint"],
            "sign": True,
            "signer_id": alice["id"],
            "signer_passphrase": "alice-passphrase",
        },
    )
    assert create_start["step"]["label"] == "Tạo chữ ký số"
    assert create_start["done"] is False
    assert create_start["result"] is None
    created = finish_create(web_server, create_start)
    opened_start = request_json(
        web_server,
        "/api/messages/open",
        {
            "user_id": bob["id"],
            "armored": created["armored"],
            "passphrase": "bob-passphrase",
        },
    )
    assert opened_start["step"]["label"] == "Tách gói tin ASCII armor"
    assert opened_start["done"] is False
    assert "message" not in opened_start
    opened = finish_open(web_server, opened_start)
    assert opened["message"] == "Xin chào Bob từ giao diện web."
    assert opened["signature"]["status"] == "valid"
    sending_labels = [step["label"] for step in created["steps"]]
    assert sending_labels == [
        "Tạo chữ ký số",
        "Nén dữ liệu",
        "Sinh khóa phiên",
        "Mã hóa lai",
        "Đóng gói ASCII armor",
    ]
    assert len(created["steps"]) == 5
    assert all(step["detail"] for step in created["steps"])
    assert "H1 =" in created["steps"][0]["value"]
    assert "AES-256-GCM" in created["steps"][3]["value"]

    bad_signer_passphrase = request_json(
        web_server,
        "/api/messages/create",
        {
            "sender_id": alice["id"],
            "message": "Sai passphrase",
            "encrypt": False,
            "sign": True,
            "signer_id": alice["id"],
            "signer_passphrase": "wrong-passphrase",
        },
    )
    assert bad_signer_passphrase["step"]["label"] == "Tạo chữ ký số"
    assert bad_signer_passphrase["step"]["status"] == "failed"
    assert bad_signer_passphrase["done"] is True

    receiving_labels = [step["label"] for step in opened["steps"]]
    assert receiving_labels == [
        "Tách gói tin ASCII armor",
        "Giải mã lấy lại khóa phiên",
        "Giải mã dữ liệu và giải nén",
        "Xác minh chữ ký số",
    ]
    assert len(opened["steps"]) == 4
    assert "H2 =" in opened["steps"][3]["value"]
    assert all(step["detail"] for step in opened["steps"])

    tampered = request_json(
        web_server, "/api/attack/tamper", {"armored": created["armored"]}
    )
    tampered_start = request_json(
        web_server,
        "/api/messages/open",
        {
            "user_id": bob["id"],
            "armored": tampered["armored"],
            "passphrase": "bob-passphrase",
        },
    )
    assert tampered_start["step"]["status"] == "success"
    assert tampered_start["step"]["label"] == "Tách gói tin ASCII armor"
    assert tampered_start["done"] is False
    tampered_steps = [tampered_start["step"]]
    tampered_progress = tampered_start
    while tampered_progress["step"]["label"] != "Giải mã dữ liệu và giải nén":
        tampered_progress = request_json(
            web_server,
            "/api/messages/open/next",
            {"session_id": tampered_progress["session_id"]},
        )
        tampered_steps.append(tampered_progress["step"])
    assert tampered_progress["step"]["status"] == "failed"
    assert tampered_progress["done"] is True
    assert all(step["status"] == "success" for step in tampered_steps[:-1])

    wrong_passphrase = open_stepwise(
        web_server,
        {
            "user_id": bob["id"],
            "armored": created["armored"],
            "passphrase": "wrong-passphrase",
        },
    )
    assert wrong_passphrase["steps"][-1]["label"] == "Giải mã lấy lại khóa phiên"
    assert wrong_passphrase["steps"][-1]["status"] == "failed"

    wrong_recipient = open_stepwise(
        web_server,
        {
            "user_id": alice["id"],
            "armored": created["armored"],
            "passphrase": "alice-passphrase",
        },
    )
    assert wrong_recipient["steps"][-1]["label"] == "Giải mã lấy lại khóa phiên"
    assert wrong_recipient["steps"][-1]["status"] == "failed"

    invalid_payload = armor.decode(created["armored"], "MESSAGE")
    invalid_payload["payload"] = "not-hex"
    invalid_payload_result = open_stepwise(
        web_server,
        {
            "user_id": bob["id"],
            "armored": armor.encode("MESSAGE", invalid_payload),
            "passphrase": "bob-passphrase",
        },
    )
    assert invalid_payload_result["steps"][-1]["label"] == "Tách gói tin ASCII armor"
    assert invalid_payload_result["steps"][-1]["status"] == "failed"

    invalid_session_key = armor.decode(created["armored"], "MESSAGE")
    invalid_session_key["encrypted_session_key"] = "not-hex"
    invalid_session_result = open_stepwise(
        web_server,
        {
            "user_id": bob["id"],
            "armored": armor.encode("MESSAGE", invalid_session_key),
            "passphrase": "bob-passphrase",
        },
    )
    assert invalid_session_result["steps"][-1]["label"] == "Giải mã lấy lại khóa phiên"
    assert invalid_session_result["steps"][-1]["status"] == "failed"

    invalid_nonce = armor.decode(created["armored"], "MESSAGE")
    invalid_nonce["nonce"] = "not-hex"
    invalid_nonce_result = open_stepwise(
        web_server,
        {
            "user_id": bob["id"],
            "armored": armor.encode("MESSAGE", invalid_nonce),
            "passphrase": "bob-passphrase",
        },
    )
    assert invalid_nonce_result["steps"][-1]["label"] == "Giải mã dữ liệu và giải nén"
    assert invalid_nonce_result["steps"][-1]["status"] == "failed"

    malformed = request_json(
        web_server,
        "/api/messages/open",
        {
            "user_id": bob["id"],
            "armored": "-----BEGIN PGP MESSAGE-----\nnot-valid-base64\n-----END PGP MESSAGE-----",
            "passphrase": "bob-passphrase",
        },
    )
    assert malformed["step"]["label"] == "Tách gói tin ASCII armor"
    assert malformed["step"]["status"] == "failed"
    assert malformed["done"] is True

    valid_json_armor = armor.encode("MESSAGE", {"x": 1})
    altered_json_armor = valid_json_armor.replace("fQ==", "fF==")
    assert altered_json_armor != valid_json_armor
    altered_json = request_json(
        web_server,
        "/api/messages/open",
        {
            "user_id": bob["id"],
            "armored": altered_json_armor,
            "passphrase": "bob-passphrase",
        },
    )
    assert altered_json["step"]["label"] == "Tách gói tin ASCII armor"
    assert altered_json["step"]["status"] == "failed"

    unsigned_encrypted = create_stepwise(
        web_server,
        {
            "sender_id": alice["id"],
            "message": "Kiểm tra lỗi chữ ký",
            "encrypt": False,
            "sign": True,
            "signer_id": alice["id"],
            "signer_passphrase": "alice-passphrase",
        },
    )
    signature_envelope = armor.decode(unsigned_encrypted["armored"], "MESSAGE")
    invalid_zlib = dict(signature_envelope)
    invalid_zlib["payload"] = "00"
    invalid_zlib_result = open_stepwise(
        web_server,
        {
            "user_id": bob["id"],
            "armored": armor.encode("MESSAGE", invalid_zlib),
            "passphrase": "",
        },
    )
    assert invalid_zlib_result["steps"][-1]["label"] == "Giải mã dữ liệu và giải nén"
    assert invalid_zlib_result["steps"][-1]["status"] == "failed"

    content = json.loads(zlib.decompress(bytes.fromhex(signature_envelope["payload"])))
    content["signature"]["value"] = "00" * len(bytes.fromhex(content["signature"]["value"]))
    signature_envelope["payload"] = zlib.compress(
        json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hex()
    invalid_signature = open_stepwise(
        web_server,
        {
            "user_id": bob["id"],
            "armored": armor.encode("MESSAGE", signature_envelope),
            "passphrase": "",
        },
    )
    assert invalid_signature["signature"]["status"] == "modified"
    assert invalid_signature["steps"][-1]["label"] == "Xác minh chữ ký số"
    assert invalid_signature["steps"][-1]["status"] == "failed"

    with pytest.raises(urllib.error.HTTPError) as eve_error:
        request_json(
            web_server,
            "/api/attack/eve",
            {"armored": created["armored"], "passphrase": "eve-passphrase"},
        )
    assert eve_error.value.code == 400
    eve_failure = json.loads(eve_error.value.read().decode("utf-8"))
    assert "khóa riêng này" in eve_failure["error"]


def test_delete_user_endpoint_prevents_deleting_last_identity(web_server: str) -> None:
    users = request_json(web_server, "/api/state")["users"]
    for user in users[:-1]:
        deleted = delete_json(web_server, "/api/users", {"user_id": user["id"]})
        assert deleted["user"]["id"] == user["id"]
        remaining = request_json(web_server, "/api/state")["users"]
        assert deleted["next_user_id"] == remaining[0]["id"]

    with pytest.raises(urllib.error.HTTPError) as last_identity:
        delete_json(web_server, "/api/users", {"user_id": users[-1]["id"]})
    assert last_identity.value.code == 400
    assert "cuối cùng" in last_identity.value.read().decode("utf-8")
