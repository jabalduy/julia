"""Private appointment requests API. Never log request bodies or decrypted client fields."""
import hashlib
import hmac
import os
import json
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import DateTime, Integer, LargeBinary, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]
ENCRYPTION_KEY = os.environ.get("FIELD_ENCRYPTION_KEY", "")
RATE_LIMIT_SECRET = os.environ.get("RATE_LIMIT_SECRET", "")
PUBLIC_ORIGIN = os.environ.get("PUBLIC_ORIGIN", "").rstrip("/")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

class Base(DeclarativeBase):
    pass

class Appointment(Base):
    __tablename__ = "appointment_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    name_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    contact_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    message_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    topic: Mapped[str] = mapped_column(String(32), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    notification_status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)

engine = None
SessionLocal = None
cipher = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, SessionLocal, cipher
    if not DATABASE_URL or not ENCRYPTION_KEY or len(RATE_LIMIT_SECRET) < 32:
        raise RuntimeError("Configure DATABASE_URL, FIELD_ENCRYPTION_KEY, RATE_LIMIT_SECRET (32+)")
    cipher = Fernet(ENCRYPTION_KEY.encode("ascii"))
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    yield
    engine.dispose()

app = FastAPI(title="Julia appointments", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "public, max-age=300"
        return response

app.add_middleware(SecurityHeaders)

class NewRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    contact: str = Field(min_length=5, max_length=160)
    topic: str = Field(max_length=32)
    message: str = Field(default="", max_length=2000)
    consent: bool
    website: str = Field(default="", max_length=200)

    @field_validator("name", "contact", "message", mode="before")
    @classmethod
    def strip_text(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator("topic")
    @classmethod
    def allowed_topics(cls, value):
        if value not in {"therapy", "supervision", "education", "cooperation"}:
            raise ValueError("Unknown topic")
        return value

def verify_same_origin(request: Request):
    origin = request.headers.get("origin", "")
    if origin:
        p = urlparse(origin)
        host = request.headers.get("host", "")
        allowed = (p.scheme == "https" and p.netloc == host) or (PUBLIC_ORIGIN and origin == PUBLIC_ORIGIN)
        if not allowed and not (p.scheme == "http" and p.netloc == host and host.startswith(("localhost:", "127.0.0.1:"))):
            raise HTTPException(status_code=403, detail="Origin not allowed")
    elif request.headers.get("sec-fetch-site", "") == "cross-site":
        raise HTTPException(status_code=403, detail="Cross-site request rejected")

def digest(value: str) -> str:
    return hmac.new(RATE_LIMIT_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()

def notify(request_id: int) -> bool:
    """Notification carries no client details."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    endpoint = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage"
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"Новая заявка на сайте Юлии №{request_id}. Откройте закрытую админку."
    }).encode("utf-8")
    req = urllib.request.Request(endpoint, payload, {"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return bool(json.load(response).get("ok"))
    except (OSError, ValueError, urllib.error.URLError):
        return False

def deliver_pending(db: Session, limit: int = 10) -> int:
    rows = db.scalars(select(Appointment).where(
        Appointment.notification_status == "pending").order_by(Appointment.id).limit(limit)).all()
    sent = 0
    for row in rows:
        if not notify(row.id):
            continue
        row.notification_status = "sent"
        db.commit()
        sent += 1
    return sent

@app.get("/api/health")
def health():
    return {"ok": True}

@app.post("/api/requests", status_code=status.HTTP_201_CREATED)
def create_request(data: NewRequest, request: Request):
    verify_same_origin(request)
    if not data.consent:
        raise HTTPException(status_code=422, detail="Consent is required")
    if data.website:
        return {"ok": True}
    # Do not save raw IP addresses; only a keyed hash, for abuse prevention.
    visitor = digest(request.client.host if request.client else "unknown")
    with SessionLocal() as db:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
        recent = db.scalar(select(func.count(Appointment.id)).where(
            Appointment.request_hash == visitor, Appointment.created_at >= cutoff))
        if recent >= 5:
            raise HTTPException(status_code=429, detail="Too many requests. Please try later.")
        row = Appointment(
            name_encrypted=cipher.encrypt(data.name.encode()),
            contact_encrypted=cipher.encrypt(data.contact.encode()),
            message_encrypted=cipher.encrypt(data.message.encode()),
            topic=data.topic, request_hash=visitor,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        deliver_pending(db)
        return {"ok": True, "request_id": row.id}

@app.get("/")
def home():
    return FileResponse(FRONTEND / "index.html", media_type="text/html")

# Import last: models defined in admin are registered before app lifespan starts.
from . import admin as admin_module
app.include_router(admin_module.router)
