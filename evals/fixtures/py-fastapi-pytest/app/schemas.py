from pydantic import BaseModel, Field


class CustomerIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+$")
    plan: str = "starter"


class Customer(BaseModel):
    id: int
    name: str
    email: str
    plan: str


class CustomerLookup(BaseModel):
    email: str = Field(min_length=3)


class LoginIn(BaseModel):
    username: str
    password: str


class SessionOut(BaseModel):
    token: str
    username: str


class PaymentIn(BaseModel):
    customer_id: int
    amount_cents: int = Field(gt=0)
    card: str


class PaymentOut(BaseModel):
    id: int
    status: str
    last4: str
