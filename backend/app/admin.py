"""Password + TOTP protected admin endpoints. Never expose client data in Telegram."""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher, exceptions as argon_errors
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import DateTime, Integer, String, delete, func, select
from sqlalchemy.orm import Mapped, mapped_column, Session

from . import main as m

router = APIRouter()
COOKIE = "__Host-julia_session"
HOURS = 8
PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
TOTP_SECRET = os.environ.get("ADMIN_TOTP_SECRET", "")
hasher = PasswordHasher()

class AdminSession(m.Base):
    __tablename__ = "admin_sessions"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class LoginFailure(m.Base):
    __tablename__ = "admin_login_failures"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class RequestState(m.Base):
    __tablename__ = "appointment_states"
    request_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)

class AuditEntry(m.Base):
    __tablename__ = "admin_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    request_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_digest: Mapped[str] = mapped_column(String(64), nullable=False)

class Login(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(pattern=r"^[0-9]{6}$")

class ChangeStatus(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def valid(cls, value):
        if value not in {"new", "contacted", "confirmed", "cancelled"}:
            raise ValueError("Invalid status")
        return value

def ip_fingerprint(request: Request):
    # Use direct TCP peer (not untrusted X-Forwarded-For).
    return m.digest(request.client.host if request.client else "unknown")

def audit(db: Session, request: Request, action: str, request_id: int | None = None):
    db.add(AuditEntry(action=action, request_id=request_id, ip_digest=ip_fingerprint(request)))

def csrf(token):
    return hmac.new(m.RATE_LIMIT_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()

def admin_token(request: Request):
    token = request.cookies.get(COOKIE, "")
    if not 40 <= len(token) <= 100:
        raise HTTPException(status_code=401, detail="Sign in required")
    with m.SessionLocal() as db:
        session = db.get(AdminSession, hashlib.sha256(token.encode()).hexdigest())
        if session is None or session.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Sign in required")
    return token

def write_guard(request: Request, token: str = Depends(admin_token)):
    m.verify_same_origin(request)
    provided = request.headers.get("x-admin-csrf", "")
    if not provided or not hmac.compare_digest(provided, csrf(token)):
        raise HTTPException(status_code=403, detail="CSRF check failed")

@router.post("/api/admin/login")
def login(data: Login, request: Request, response: Response):
    m.verify_same_origin(request)
    if not PASSWORD_HASH.startswith("$argon2id$") or not TOTP_SECRET:
        raise HTTPException(status_code=503, detail="Admin is not configured")
    ip = ip_fingerprint(request)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
    with m.SessionLocal() as db:
        per_ip = db.scalar(select(func.count(LoginFailure.id)).where(
            LoginFailure.ip_digest == ip, LoginFailure.created_at >= cutoff))
        total = db.scalar(select(func.count(LoginFailure.id)).where(LoginFailure.created_at >= cutoff))
        if per_ip >= 5 or total >= 30:
            raise HTTPException(status_code=429, detail="Too many login attempts")
        try:
            password_ok = hasher.verify(PASSWORD_HASH, data.password)
        except (argon_errors.VerifyMismatchError, argon_errors.VerificationError, argon_errors.InvalidHashError):
            password_ok = False
        code_ok = pyotp.TOTP(TOTP_SECRET).verify(data.code, valid_window=1)
        if not password_ok or not code_ok:
            db.add(LoginFailure(ip_digest=ip))
            audit(db, request, "login_failed")
            db.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = secrets.token_urlsafe(48)
        db.add(AdminSession(digest=hashlib.sha256(token.encode()).hexdigest(),
                            expires_at=datetime.now(timezone.utc) + timedelta(hours=HOURS)))
        audit(db, request, "login")
        db.commit()
    response.set_cookie(COOKIE, token, max_age=HOURS*3600,
                        secure=True, httponly=True, samesite="strict", path="/")
    return {"ok": True, "csrf": csrf(token)}

@router.get("/api/admin/session")
def session(token: str = Depends(admin_token)):
    return {"authenticated": True, "csrf": csrf(token)}

@router.post("/api/admin/logout")
def logout(request: Request, response: Response, _=Depends(write_guard)):
    token = request.cookies.get(COOKIE, "")
    with m.SessionLocal() as db:
        db.execute(delete(AdminSession).where(AdminSession.digest == hashlib.sha256(token.encode()).hexdigest()))
        audit(db, request, "logout")
        db.commit()
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"ok": True}

@router.get("/api/admin/requests")
def list_requests(request: Request, limit: int = 50, _=Depends(admin_token)):
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 100")
    with m.SessionLocal() as db:
        rows = db.scalars(select(m.Appointment).order_by(m.Appointment.id.desc()).limit(limit)).all()
        states = dict(db.execute(select(RequestState.request_id, RequestState.status).where(
            RequestState.request_id.in_([row.id for row in rows]))).all()) if rows else {}
        result = [{
            "id": r.id, "created_at": r.created_at.isoformat(), "topic": r.topic,
            "name": m.cipher.decrypt(r.name_encrypted).decode(),
            "contact": m.cipher.decrypt(r.contact_encrypted).decode(),
            "message": m.cipher.decrypt(r.message_encrypted).decode(),
            "status": states.get(r.id, "new"),
            "notification_status": r.notification_status,
        } for r in rows]
        audit(db, request, "list_requests")
        db.commit()
    return {"requests": result}

@router.patch("/api/admin/requests/{request_id}")
def update_status(request_id: int, data: ChangeStatus, request: Request, _=Depends(write_guard)):
    with m.SessionLocal() as db:
        if db.get(m.Appointment, request_id) is None:
            raise HTTPException(status_code=404, detail="Request not found")
        state = db.get(RequestState, request_id)
        if state is None:
            db.add(RequestState(request_id=request_id, status=data.status))
        else:
            state.status = data.status
        audit(db, request, "update_status", request_id)
        db.commit()
    return {"ok": True}

@router.delete("/api/admin/requests/{request_id}")
def delete_request(request_id: int, request: Request, _=Depends(write_guard)):
    with m.SessionLocal() as db:
        row = db.get(m.Appointment, request_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Request not found")
        state = db.get(RequestState, request_id)
        if state is not None:
            db.delete(state)
        db.delete(row)
        audit(db, request, "delete_request", request_id)
        db.commit()
    return {"ok": True}

@router.post("/api/admin/notifications/retry")
def retry_notifications(request: Request, _=Depends(write_guard)):
    with m.SessionLocal() as db:
        sent = m.deliver_pending(db)
        audit(db, request, "retry_notifications")
        db.commit()
    return {"sent": sent}

@router.get("/admin")
def admin_page():
    return FileResponse(m.FRONTEND / "admin.html", media_type="text/html",
                        headers={"Content-Security-Policy":
                            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})

@router.get("/admin.js")
def admin_script():
    return FileResponse(m.FRONTEND / "admin.js", media_type="application/javascript")

@router.get("/admin.css")
def admin_style():
    return FileResponse(m.FRONTEND / "admin.css", media_type="text/css")
