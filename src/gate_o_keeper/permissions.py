"""A read-through integration point for any authoritative directory."""

from typing import Protocol

import requests


class DirectoryUnavailable(Exception):
    pass


class PermissionSource(Protocol):
    def allowed(self, key: str) -> bool: ...


class HttpDirectory:
    def __init__(self, url: str, token: str):
        self.url = url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def read(self, url, params=None):
        try:
            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                timeout=(2, 4),
                allow_redirects=False,
            )
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise DirectoryUnavailable
            data = response.json()
            if not isinstance(data, dict):
                raise DirectoryUnavailable
            return data
        except (requests.RequestException, ValueError) as exc:
            raise DirectoryUnavailable from exc

    def allowed(self, key: str) -> bool:
        data = self.read(self.url, {"subject": key})
        if data is None:
            return False
        if data.get("subject") != key or type(data.get("allowed")) is not bool:
            raise DirectoryUnavailable
        return data["allowed"]


class AuthentikDirectory(HttpDirectory):
    def __init__(self, url: str, token: str, group: str):
        super().__init__(url, token)
        self.group = group

    def allowed(self, key: str) -> bool:
        if not key.isascii() or not key.isdecimal():
            return False
        data = self.read(f"{self.url.rstrip('/')}/{key}/")
        if data is None:
            return False
        if str(data.get("pk")) != key or type(data.get("is_active")) is not bool:
            raise DirectoryUnavailable
        groups = data.get("groups")
        if not isinstance(groups, list) or not all(
            isinstance(group, str) for group in groups
        ):
            raise DirectoryUnavailable
        return data["is_active"] and self.group in groups
