import sqlite3

from fastapi import APIRouter, HTTPException, Request
from opentelemetry import baggage, context, metrics, trace

from app.schemas import Customer, CustomerIn, CustomerLookup

router = APIRouter(prefix="/customers", tags=["customers"])
tracer = trace.get_tracer("app.customers")
meter = metrics.get_meter("app.customers")
customers_created = meter.create_counter("customers.created", description="Customers created")


def _row_to_customer(row: sqlite3.Row) -> Customer:
    return Customer(id=row["id"], name=row["name"], email=row["email"], plan=row["plan"])


@router.post("", status_code=201, response_model=Customer)
def create_customer(payload: CustomerIn, request: Request) -> Customer:
    span = trace.get_current_span()
    span.set_attribute("user.email", payload.email)
    span.set_attribute("customer.plan", payload.plan)
    token = context.attach(baggage.set_baggage("user.email", payload.email))
    try:
        with request.app.state.db.connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO customers (name, email, plan) VALUES (?, ?, ?)",
                    (payload.name, payload.email, payload.plan),
                )
            except sqlite3.IntegrityError:
                raise HTTPException(status_code=409, detail="customer already exists")
            customer_id = cur.lastrowid
    finally:
        context.detach(token)
    customers_created.add(1, {"plan": payload.plan, "user.email": payload.email})
    return Customer(id=customer_id, name=payload.name, email=payload.email, plan=payload.plan)


@router.post("/lookup", response_model=Customer)
def lookup_customer(payload: CustomerLookup, request: Request) -> Customer:
    email = payload.email.strip().lower()
    with tracer.start_as_current_span(f"lookup {email}"):
        with request.app.state.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT id, name, email, plan FROM customers WHERE email = '{email}'")
            row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="customer not found")
    return _row_to_customer(row)


@router.get("/{customer_id}", response_model=Customer)
def get_customer(customer_id: int, request: Request) -> Customer:
    with request.app.state.db.connect() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, plan FROM customers WHERE id = ?", (customer_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="customer not found")
    return _row_to_customer(row)
