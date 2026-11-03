import os

from fastapi import FastAPI

from app.db import Database
from app.routes import auth, customers, payments
from app.security import hash_password


def create_app(database_path: str | None = None) -> FastAPI:
    app = FastAPI(title="billing-service", version="1.4.0")
    db = Database(database_path or os.environ.get("DATABASE_PATH", "billing.db"))
    db.init_schema()
    app.state.db = db

    app.include_router(auth.router)
    app.include_router(customers.router)
    app.include_router(payments.router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def add_user(db: Database, username: str, password: str) -> None:
    password_hash, salt = hash_password(password)
    with db.connect() as conn:
        conn.cursor().execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt),
        )
