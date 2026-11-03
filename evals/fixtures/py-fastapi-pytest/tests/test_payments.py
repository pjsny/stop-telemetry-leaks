def test_payment_captured(client, customer):
    response = client.post(
        "/payments",
        json={"customer_id": customer["id"], "amount_cents": 4900, "card": "4242 4242 4242 4242"},
    )
    assert response.status_code == 201
    assert response.json() == {"id": 1, "status": "captured", "last4": "4242"}


def test_payment_with_bad_card(client, customer):
    response = client.post(
        "/payments",
        json={"customer_id": customer["id"], "amount_cents": 4900, "card": "4242 4242 4242 4241"},
    )
    assert response.status_code == 422


def test_payment_for_unknown_customer(client):
    response = client.post(
        "/payments",
        json={"customer_id": 999, "amount_cents": 100, "card": "4242424242424242"},
    )
    assert response.status_code == 404
