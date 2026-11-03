from fastapi import APIRouter, HTTPException, Request
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from app.schemas import PaymentIn, PaymentOut
from app.security import luhn_valid

router = APIRouter(prefix="/payments", tags=["payments"])


@router.post("", status_code=201, response_model=PaymentOut)
def create_payment(payload: PaymentIn, request: Request) -> PaymentOut:
    span = trace.get_current_span()
    span.set_attribute("payment.amount_cents", payload.amount_cents)
    card = payload.card.replace(" ", "")
    if not luhn_valid(card):
        error = ValueError(f"invalid card {payload.card}")
        span.record_exception(error)
        span.set_status(Status(StatusCode.ERROR, "card rejected"))
        raise HTTPException(status_code=422, detail="card number is not valid")

    with request.app.state.db.connect() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM customers WHERE id = ?", (payload.customer_id,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="customer not found")
        cur.execute(
            "INSERT INTO payments (customer_id, amount_cents, last4, status) VALUES (?, ?, ?, ?)",
            (payload.customer_id, payload.amount_cents, card[-4:], "captured"),
        )
        payment_id = cur.lastrowid
    return PaymentOut(id=payment_id, status="captured", last4=card[-4:])
