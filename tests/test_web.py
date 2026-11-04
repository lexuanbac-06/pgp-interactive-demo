from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

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


def test_web_ui_hybrid_signed_message_flow(web_server: str) -> None:
    page = urllib.request.urlopen(web_server + "/").read().decode("utf-8")
    assert "Soạn tin nhắn" in page
    assert "Giải mã &amp; xác minh" in page

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

    created = request_json(
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
    opened = request_json(
        web_server,
        "/api/messages/open",
        {
            "user_id": bob["id"],
            "armored": created["armored"],
            "passphrase": "bob-passphrase",
        },
    )
    assert opened["message"] == "Xin chào Bob từ giao diện web."
    assert opened["signature"]["status"] == "valid"
    assert len(created["steps"]) >= 5

    tampered = request_json(
        web_server, "/api/attack/tamper", {"armored": created["armored"]}
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        request_json(
            web_server,
            "/api/messages/open",
            {
                "user_id": bob["id"],
                "armored": tampered["armored"],
                "passphrase": "bob-passphrase",
            },
        )
    assert error.value.code == 400
    failure = json.loads(error.value.read().decode("utf-8"))
    assert "AES-GCM" in failure["error"]

    with pytest.raises(urllib.error.HTTPError) as eve_error:
        request_json(
            web_server,
            "/api/attack/eve",
            {"armored": created["armored"], "passphrase": "eve-passphrase"},
        )
    assert eve_error.value.code == 400
    eve_failure = json.loads(eve_error.value.read().decode("utf-8"))
    assert "khóa riêng này" in eve_failure["error"]
