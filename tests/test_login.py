"""End-to-end OIDC redirects and signatures with an in-process identity provider."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from conftest import csrf, get_visit
from joserfc import jwt
from joserfc.jwk import RSAKey

from gate_o_keeper.web import MEMBER_COOKIE


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, {"kid": "local-test"})


@pytest.mark.parametrize("invalid", [None, "state", "iss", "aud", "nonce", "exp"])
def test_oidc_callback(app, settings, monkeypatch, signing_key, invalid):
    client = app.test_client()
    visit = get_visit(client)
    params = {}
    issuer = settings.issuer
    now = int(time.time())

    def send(_session, request, **kwargs):
        if request.url == issuer + ".well-known/openid-configuration":
            data = {
                "issuer": issuer,
                "authorization_endpoint": issuer + "authorize",
                "token_endpoint": issuer + "token",
                "jwks_uri": issuer + "keys",
                "id_token_signing_alg_values_supported": ["RS256"],
            }
        elif request.url == issuer + "keys":
            data = {"keys": [signing_key.as_dict(private=False)]}
        elif request.url == issuer + "token":
            form = parse_qs(request.body)
            assert form["redirect_uri"] == [settings.origin + "/auth/callback"]
            verifier = hashlib.sha256(form["code_verifier"][0].encode()).digest()
            assert params["code_challenge"] == [
                base64.urlsafe_b64encode(verifier).decode().rstrip("=")
            ]
            claims = {
                "iss": issuer,
                "aud": settings.client_id,
                "sub": "alice",
                "member_id": 17,
                "iat": now - 600,
                "exp": now + 60,
                "nonce": params["nonce"][0],
            }
            if invalid in claims:
                claims[invalid] = now - 500 if invalid == "exp" else "wrong-value"
            data = {
                "token_type": "Bearer",
                "access_token": "local-test-only",
                "id_token": jwt.encode(
                    {"alg": "RS256", "kid": "local-test"}, claims, signing_key
                ),
            }
        else:
            pytest.fail("Unexpected upstream URL")
        result = requests.Response()
        result.status_code = 200
        result._content = json.dumps(data).encode()
        result.headers["Content-Type"] = "application/json"
        return result

    monkeypatch.setattr(requests.Session, "send", send)
    login = client.get("/login", query_string={"visit": visit.rsplit("/", 1)[1]})
    assert login.status_code == 302
    params.update(parse_qs(urlsplit(login.location).query))
    assert params["code_challenge_method"] == ["S256"]
    response = client.get(
        "/auth/callback",
        query_string={
            "state": "unknown" if invalid == "state" else params["state"][0],
            "code": "test-code",
        },
    )
    if invalid:
        assert response.status_code == 401
        assert client.get_cookie(MEMBER_COOKIE, domain="gate.test") is None
        return
    assert response.status_code == 303 and response.location == visit
    page = client.get(response.location)
    assert "确认本次开门" in page.text
    token = client.get_cookie(MEMBER_COOKIE, domain="gate.test").value
    assert client.post("/logout", data={"csrf": csrf(page)}).status_code == 303
    assert not app.extensions["gate_store"].member(token)
