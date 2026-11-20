import re
from urllib.parse import urlsplit

import pytest

from gate_o_keeper.config import Policy, Settings
from gate_o_keeper.hardware import DoorRelay, Ntag424, RelayResult
from gate_o_keeper.permissions import DirectoryUnavailable
from gate_o_keeper.web import create_app

ORIGIN = "https://gate.test"
# Published NXP AN12196 table 4 conformance vector, only used by these tests.
TAP = "/d/front?e=EF963FF7828658A599F3041510671E88&c=94EED9EE65337086"


class Directory:
    result = True

    def allowed(self, key):
        assert key == "17"
        if self.result is None:
            raise DirectoryUnavailable
        return self.result


class Relay(DoorRelay):
    def __init__(self):
        self.calls = []
        self.timeout = False

    def unlock(self, door, command_id):
        self.calls.append((door, command_id))
        if self.timeout:
            raise TimeoutError
        return RelayResult.CONFIRMED


@pytest.fixture
def settings(tmp_path):
    return Settings(
        database=tmp_path / "gate.db",
        origin=ORIGIN,
        issuer="https://id.test/app/",
        client_id="club",
        client_secret="test-secret",
        secret="s" * 40,
        webhook_secret="w" * 40,
        permission_backend="http",
        permission_url="https://dir.test/check",
        api_token="test",
        group="",
        lookup_claim="member_id",
        scope="openid profile",
        doors={"front": Ntag424(bytes.fromhex("04DE5F1EACC040"), bytes(16), bytes(16))},
        policy=Policy(
            session_seconds=100, offline_seconds=110, poll_seconds=10, scan_seconds=30
        ),
    )


@pytest.fixture
def relay():
    return Relay()


@pytest.fixture
def source():
    return Directory()


@pytest.fixture
def app(settings, relay, source):
    application = create_app(settings, source=source, relay=relay)
    application.config.update(
        TESTING=True, SERVER_NAME="gate.test", PREFERRED_URL_SCHEME="https"
    )
    return application


def get_visit(client):
    page = client.get(TAP)
    assert page.status_code == 200
    return urlsplit(
        re.search(r'id="share" readonly value="([^"]+)"', page.text)[1]
    ).path


def csrf(page):
    return re.search(r'name="csrf" value="([^"]+)"', page.text)[1]


def signed_in(app):
    from gate_o_keeper.web import MEMBER_COOKIE

    token, expiry = app.extensions["gate_permissions"].check("alice", "17")
    client = app.test_client()
    client.set_cookie(MEMBER_COOKIE, token, domain="gate.test", secure=True)
    return client, token, expiry
