import os
from pathlib import Path

import pyotp
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

DB = Path("/tmp/julia-tests.sqlite3")
if DB.exists():
    DB.unlink()
os.environ["DATABASE_URL"] = "sqlite:///" + str(DB)
os.environ["FIELD_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["RATE_LIMIT_SECRET"] = "test-" + "z" * 45
os.environ["ADMIN_PASSWORD_HASH"] = PasswordHasher().hash("a-long-test-password")
os.environ["ADMIN_TOTP_SECRET"] = pyotp.random_base32()
os.environ.pop("TELEGRAM_BOT_TOKEN", None)
os.environ.pop("TELEGRAM_CHAT_ID", None)

from backend.app import main  # noqa: E402

def test_app():
    with TestClient(main.app, base_url="https://testserver") as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert client.get("/admin").status_code == 200
        assert client.get("/api/admin/requests").status_code == 401
        request = {"name": "Ирина", "contact": "@irina_contact", "topic": "therapy",
                   "message": "Очень личный текст", "consent": True, "website": ""}
        refused = client.post("/api/requests", json={**request, "consent": False})
        assert refused.status_code == 422
        saved = client.post("/api/requests", json=request)
        assert saved.status_code == 201
        rid = saved.json()["request_id"]
        assert client.get("/api/admin/requests").status_code == 401

        # Sensitive values are encrypted at rest; never sent to Telegram.
        with main.SessionLocal() as db:
            row = db.get(main.Appointment, rid)
            assert b"\xd0\x98\xd1\x80\xd0\xb8\xd0\xbd\xd0\xb0" not in row.name_encrypted
            assert b"@irina_contact" not in row.contact_encrypted
            assert b"\xd0\x9e\xd1\x87\xd0\xb5\xd0\xbd\xd1\x8c" not in row.message_encrypted
            assert row.notification_status == "pending"
        assert client.post("/api/admin/login", json={"password": "wrong", "code": "000000"}).status_code == 401
        credentials = {"password": "a-long-test-password",
                       "code": pyotp.TOTP(os.environ["ADMIN_TOTP_SECRET"]).now()}
        login = client.post("/api/admin/login", json=credentials)
        assert login.status_code == 200
        assert "Secure" in login.headers["set-cookie"]
        assert "HttpOnly" in login.headers["set-cookie"]
        csrf = login.json()["csrf"]
        entries = client.get("/api/admin/requests")
        assert entries.status_code == 200
        assert entries.json()["requests"][0]["contact"] == "@irina_contact"
        # Explicit anti-CSRF protection for writes.
        assert client.patch(f"/api/admin/requests/{rid}", json={"status": "contacted"}).status_code == 403
        patch = client.patch(f"/api/admin/requests/{rid}", json={"status": "contacted"},
                             headers={"x-admin-csrf": csrf})
        assert patch.status_code == 200
        assert client.get("/api/admin/requests").json()["requests"][0]["status"] == "contacted"
        assert client.patch(f"/api/admin/requests/{rid}", json={"status": "invalid"},
                            headers={"x-admin-csrf": csrf}).status_code == 422
        deleted = client.delete(f"/api/admin/requests/{rid}", headers={"x-admin-csrf": csrf})
        assert deleted.status_code == 200
        assert client.get("/api/admin/requests").json()["requests"] == []
        assert client.post("/api/admin/logout", headers={"x-admin-csrf": csrf}).status_code == 200
        assert client.get("/api/admin/requests").status_code == 401
