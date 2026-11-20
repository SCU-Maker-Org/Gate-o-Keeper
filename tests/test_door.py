from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from conftest import TAP, csrf, get_visit, signed_in

from gate_o_keeper.hardware import Scan
from gate_o_keeper.store import Denied, Store
from gate_o_keeper.web import MEMBER_COOKIE


def test_forwarded_visit_only_opens_once(app, relay):
    guest = app.test_client()
    visit = get_visit(guest)
    assert get_visit(guest) == visit
    guest.get(visit)
    with guest.session_transaction() as session:
        guest_csrf = session["csrf"]
    assert guest.post(visit + "/open", data={"csrf": guest_csrf}).status_code == 403
    member, _, _ = signed_in(app)
    page = member.get(visit)
    assert "data-auto" not in page.text
    assert member.post(visit + "/open").status_code == 403
    assert (
        member.post(
            visit + "/open",
            data={"csrf": csrf(page)},
            headers={"Origin": "https://elsewhere.test"},
        ).status_code
        == 403
    )
    assert not relay.calls
    assert member.post(visit + "/open", data={"csrf": csrf(page)}).status_code == 200
    assert guest.get(TAP).status_code == 403
    assert member.post(visit + "/open", data={"csrf": csrf(page)}).status_code == 403
    assert len(relay.calls) == 1


def test_nxp_vector_and_direct_scan(app, relay):
    client, _, _ = signed_in(app)
    response = client.get(
        TAP,
        headers={
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
        },
    )
    assert "data-auto" in response.text
    assert response.headers["Referrer-Policy"] == "strict-origin"
    assert not relay.calls
    store = app.extensions["gate_store"]
    with store.connection() as db:
        assert db.execute("SELECT counter FROM visits").fetchone()[0] == 61
        assert not db.execute("SELECT * FROM tags").fetchall()
    assert client.get(TAP[:-1] + "0").status_code == 400
    assert client.get(TAP + "&e=duplicate").status_code == 400


def test_deadline_starts_on_first_presentation(app):
    client = app.test_client()
    store = app.extensions["gate_store"]
    store.clock = lambda: 1000
    visit = get_visit(client)
    store.clock = lambda: 1030
    assert client.get(TAP).status_code == 403
    assert client.get(visit).status_code == 403


def test_member_cookie_renewal_matches_database(app):
    store = app.extensions["gate_store"]
    store.clock = lambda: 2000000000
    client, _, expiry = signed_in(app)
    store.clock = lambda: 2000000005
    visit = get_visit(client)
    response = client.post(visit + "/open", data={"csrf": csrf(client.get(visit))})
    cookie = client.get_cookie(MEMBER_COOKIE, domain="gate.test")
    assert response.status_code == 200
    assert cookie.http_only and cookie.secure and cookie.same_site == "Lax"
    assert cookie.expires.timestamp() == expiry + 5
    with store.connection() as db:
        assert db.execute("SELECT expires FROM sessions").fetchone()[0] == expiry + 5


def test_offline_open_never_extends_lease(app, source):
    store = app.extensions["gate_store"]
    store.clock = lambda: 1000
    client, token, expiry = signed_in(app)
    source.result = None
    store.clock = lambda: 1005
    app.extensions["gate_permissions"].poll()
    visit = get_visit(client)
    response = client.post(visit + "/open", data={"csrf": csrf(client.get(visit))})
    assert response.status_code == 200
    assert all(MEMBER_COOKIE not in h for h in response.headers.getlist("Set-Cookie"))
    store.clock = lambda: expiry
    assert not store.member(token)


def test_hardware_timeout_is_never_retried(app, relay, settings):
    relay.timeout = True
    client, _, _ = signed_in(app)
    visit = get_visit(client)
    form = {"csrf": csrf(client.get(visit))}
    assert client.post(visit + "/open", data=form).status_code == 502
    assert client.post(visit + "/open", data=form).status_code == 403
    assert len(relay.calls) == 1
    with app.extensions["gate_store"].connection() as db:
        assert db.execute("SELECT outcome FROM attempts").fetchone()[0] == "unknown"
        assert not db.execute("SELECT * FROM tags").fetchall()
        namespace = db.execute("SELECT value FROM settings").fetchone()[0]
    reopened = Store(settings.database, settings.policy, namespace)
    with pytest.raises(Denied):
        reopened.visit(visit.split("/")[-1])


def test_concurrent_confirmations(app, relay):
    visit = get_visit(app.test_client())
    clients = [signed_in(app)[0] for _ in range(4)]
    forms = [csrf(client.get(visit)) for client in clients]
    barrier = Barrier(len(clients))

    def submit(pair):
        client, value = pair
        barrier.wait(timeout=3)
        return client.post(visit + "/open", data={"csrf": value}).status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = sorted(pool.map(submit, zip(clients, forms, strict=True)))
    assert statuses == [200, 403, 403, 403]
    assert len(relay.calls) == 1


def test_only_success_advances_counter_and_invalidates_older_visits(app):
    store = app.extensions["gate_store"]
    _, token, _ = signed_in(app)
    for counter in (5, 9):
        store.register_scan("front", Scan("test-tag", counter), str(counter))
    assert store.visit("5")
    attempt = store.claim("9", token)
    store.finish_attempt(attempt, "confirmed", token)
    with pytest.raises(Denied):
        store.claim("5", token)
    with pytest.raises(Denied):
        store.register_scan("front", Scan("test-tag", 7), "7")


def test_poll_revoke_and_authenticated_webhook(app, source):
    client, token, _ = signed_in(app)
    store = app.extensions["gate_store"]
    route = "/webhooks/permissions"
    headers = {"Authorization": "Bearer " + "w" * 40}
    body = {"event": "revoke", "subject": "alice"}
    assert client.post(route, json=body).status_code == 401
    assert store.member(token)
    old = store.begin_check("alice")
    assert client.post(route, json=body, headers=headers).status_code == 204
    assert not store.finish_check("alice", old["revision"], True, sign_in=True)
    assert not store.member(token)
    _, token, _ = signed_in(app)
    source.result = False
    app.extensions["gate_permissions"].poll()
    assert not store.member(token)
    assert (
        client.post(route, json={"event": "refresh"}, headers=headers).status_code
        == 202
    )
    assert app.extensions["gate_permissions"].wakeup.is_set()


def test_webhook_refresh_updates_sessions_and_outage_cannot_create_one(app, source):
    from gate_o_keeper.permissions import DirectoryUnavailable

    client, token, _ = signed_in(app)
    route = "/webhooks/permissions"
    kwargs = {
        "headers": {"Authorization": "Bearer " + "w" * 40},
        "json": {"event": "refresh", "subject": "alice"},
    }
    source.result = None
    assert client.post(route, **kwargs).status_code == 503
    assert app.extensions["gate_store"].member(token)
    with pytest.raises(DirectoryUnavailable):
        app.extensions["gate_permissions"].check("new-member", "17")
    source.result = False
    assert client.post(route, **kwargs).status_code == 204
    assert not app.extensions["gate_store"].member(token)
