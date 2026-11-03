import logging

from fastapi import APIRouter, HTTPException, Request
from opentelemetry import trace

from app.schemas import LoginIn, SessionOut
from app.security import issue_session_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger("app.auth")


@router.post("/login", response_model=SessionOut)
def login(payload: LoginIn, request: Request) -> SessionOut:
    span = trace.get_current_span()
    span.set_attribute("enduser.id", payload.username)
    logger.info("login %s password=%s", payload.username, payload.password)
    with request.app.state.db.connect() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username = ?", (payload.username,))
        row = cur.fetchone()
    if row is None or not verify_password(payload.password, row["password_hash"], row["salt"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return SessionOut(token=issue_session_token(), username=payload.username)
