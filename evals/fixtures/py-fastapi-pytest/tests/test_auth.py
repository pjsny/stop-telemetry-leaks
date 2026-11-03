def test_login_success(client, user):
    response = client.post("/auth/login", json=user)
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "jordan"
    assert len(body["token"]) > 20


def test_login_wrong_password(client, user):
    response = client.post("/auth/login", json={"username": "jordan", "password": "nope"})
    assert response.status_code == 401


def test_login_unknown_user(client):
    response = client.post("/auth/login", json={"username": "ghost", "password": "whatever"})
    assert response.status_code == 401
