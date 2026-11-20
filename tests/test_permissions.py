from unittest.mock import Mock

import pytest

from gate_o_keeper.permissions import (
    AuthentikDirectory,
    DirectoryUnavailable,
    HttpDirectory,
)


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (200, {"pk": 17, "is_active": True, "groups": ["club"]}, True),
        (200, {"pk": "17", "is_active": False, "groups": ["club"]}, False),
        (200, {"pk": 17, "is_active": True, "groups": []}, False),
        (404, None, False),
        (403, None, None),
        (503, None, None),
        (200, {"pk": 18, "is_active": True, "groups": ["club"]}, None),
        (200, {"pk": 17, "is_active": "false", "groups": ["club"]}, None),
    ],
)
def test_authentik_adapter(monkeypatch, status, payload, expected):
    response = Mock(status_code=status)
    response.json.return_value = payload
    fetch = Mock(return_value=response)
    monkeypatch.setattr("requests.get", fetch)
    directory = AuthentikDirectory(
        "https://id.test/api/v3/core/users/", "secret", "club"
    )
    if expected is None:
        with pytest.raises(DirectoryUnavailable):
            directory.allowed("17")
    else:
        assert directory.allowed("17") is expected
    assert fetch.call_args.args == ("https://id.test/api/v3/core/users/17/",)
    assert not fetch.call_args.kwargs["allow_redirects"]


def test_generic_directory(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = {"subject": "a/b", "allowed": True}
    fetch = Mock(return_value=response)
    monkeypatch.setattr("requests.get", fetch)
    directory = HttpDirectory("https://permissions.test/check", "secret")
    assert directory.allowed("a/b")
    assert fetch.call_args.kwargs["params"] == {"subject": "a/b"}
    with pytest.raises(DirectoryUnavailable):
        directory.allowed("other")
