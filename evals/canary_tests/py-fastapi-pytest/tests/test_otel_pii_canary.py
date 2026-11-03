"""Canary requests through every route of the billing service (copied in by evals/score.py)."""

import os

SEED = os.environ["OTEL_PII_CANARY_SEED"]
TOKEN = f"otelcanary_{SEED}"
EMAIL = f"canary+{SEED}@example.invalid"
CARD = "4111111111111111"
NAME = f"Canary Person {SEED}"
HEADERS = {
    "authorization": f"Bearer {TOKEN}",
    "cookie": f"session={TOKEN}",
    "x-api-key": TOKEN,
}


def test_otel_pii_canary_requests(client):
    q = f"?api_key={TOKEN}"
    client.get(f"/healthz{q}", headers=HEADERS)
    created = client.post(f"/customers{q}", json={"name": NAME, "email": EMAIL, "plan": "team"}, headers=HEADERS)
    customer_id = created.json().get("id", 1)
    client.post(f"/customers/lookup{q}", json={"email": EMAIL}, headers=HEADERS)
    client.get(f"/customers/{customer_id}{q}", headers=HEADERS)
    client.post(f"/auth/login{q}", json={"username": EMAIL, "password": TOKEN}, headers=HEADERS)
    # Not Luhn-valid as a whole: drives the card-rejection exception path with canary input.
    client.post(f"/payments{q}", json={"customer_id": customer_id, "amount_cents": 100, "card": f"{CARD} {TOKEN}"},
                headers=HEADERS)
    client.post(f"/payments{q}", json={"customer_id": customer_id, "amount_cents": 100, "card": CARD}, headers=HEADERS)
