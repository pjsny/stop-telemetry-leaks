def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_create_customer(customer):
    assert customer["id"] > 0
    assert customer["plan"] == "team"


def test_duplicate_customer_is_rejected(client, customer):
    response = client.post(
        "/customers",
        json={"name": "Jordan Rivera", "email": "jordan@example.com"},
    )
    assert response.status_code == 409


def test_invalid_email_is_rejected(client):
    response = client.post("/customers", json={"name": "Sam", "email": "not-an-email"})
    assert response.status_code == 422


def test_get_customer(client, customer):
    response = client.get(f"/customers/{customer['id']}")
    assert response.status_code == 200
    assert response.json()["email"] == "jordan@example.com"


def test_lookup_customer_by_email(client, customer):
    response = client.post("/customers/lookup", json={"email": "Jordan@Example.com"})
    assert response.status_code == 200
    assert response.json()["id"] == customer["id"]


def test_lookup_unknown_customer(client):
    response = client.post("/customers/lookup", json={"email": "nobody@example.com"})
    assert response.status_code == 404
