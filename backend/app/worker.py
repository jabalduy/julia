"""One-shot Telegram outbox retry. Run as a separate Railway Cron service every 5 min."""
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from . import main

def run() -> int:
    if not main.DATABASE_URL or not main.TELEGRAM_BOT_TOKEN or not main.TELEGRAM_CHAT_ID:
        print("Missing database or Telegram configuration", file=sys.stderr)
        return 1
    engine = create_engine(main.DATABASE_URL, pool_pre_ping=True)
    try:
        with Session(engine) as db:
            pending = db.scalar(__import__("sqlalchemy").select(__import__("sqlalchemy").func.count(main.Appointment.id)).where(
                main.Appointment.notification_status == "pending"))
            sent = main.deliver_pending(db, limit=50)
            print(f"Telegram retry complete: pending_before={pending}, sent={sent}")
        return 0
    finally:
        engine.dispose()

if __name__ == "__main__":
    sys.exit(run())
