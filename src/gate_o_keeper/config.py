import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from .hardware import Ntag424, ScanVerifier


@dataclass(frozen=True)
class Policy:
    session_seconds: int = 8 * 3600
    offline_seconds: int = 24 * 3600
    poll_seconds: int = 60
    scan_seconds: int = 180

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError("各项时限须为正整数秒")


@dataclass(frozen=True)
class Settings:
    database: Path
    origin: str
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    secret: str = field(repr=False)
    webhook_secret: str = field(repr=False)
    permission_backend: str
    permission_url: str
    api_token: str = field(repr=False)
    group: str
    lookup_claim: str
    scope: str
    doors: dict[str, ScanVerifier] = field(repr=False)
    policy: Policy
    relay_factory: str = ""
    discovery_url: str = ""


def https_url(url: str, *, origin=False) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.query
        or parsed.fragment
        or (origin and parsed.path.strip("/"))
    ):
        raise ValueError("服务地址须为 HTTPS 地址，站点地址仅包含域名和可选端口")
    return url


def load(path: Path) -> Settings:
    with path.open("rb") as stream:
        config = tomllib.load(stream)
    oidc, directory = config["oidc"], config["permissions"]
    doors = {}
    uids = set()
    for name, tag in config["doors"].items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError("门编号格式无效")
        uid = bytes.fromhex(tag["uid"])
        keys = [
            bytes.fromhex(os.environ[tag[k]]) for k in ("meta_key_env", "file_key_env")
        ]
        if (
            len(uid) != 7
            or uid in uids
            or any(len(key) != 16 or not any(key) for key in keys)
        ):
            raise ValueError(
                "每张贴纸须有独立的七字节 UID，并配置非出厂的 AES-128 密钥"
            )
        uids.add(uid)
        doors[name] = Ntag424(uid, *keys)
    if not doors:
        raise ValueError("至少需要配置一扇门")
    secret, webhook = os.environ["GATE_SECRET"], os.environ["GATE_WEBHOOK_SECRET"]
    if (
        min(len(secret), len(webhook)) < 32
        or secret == webhook
        or not webhook.isascii()
    ):
        raise ValueError(
            "站点签名和 webhook 须使用独立的长随机密钥，webhook 使用 ASCII"
        )
    backend = directory["backend"]
    if backend not in {"authentik", "http"}:
        raise ValueError("未知的权限适配器")
    group = str(UUID(directory["group_uuid"])) if backend == "authentik" else ""
    scope = oidc.get("scope", "openid profile")
    if "openid" not in scope.split():
        raise ValueError("登录 scope 必须包含 openid")
    return Settings(
        path.parent / config.get("database", "gate.sqlite3"),
        https_url(config["origin"], origin=True).rstrip("/"),
        https_url(oidc["issuer"]),
        oidc["client_id"],
        os.environ["GATE_OIDC_SECRET"],
        secret,
        webhook,
        backend,
        https_url(directory["url"]),
        os.environ["GATE_DIRECTORY_TOKEN"],
        group,
        directory.get("lookup_claim", "sub"),
        scope,
        doors,
        Policy(**config.get("policy", {})),
        config.get("relay_factory", ""),
        https_url(oidc["discovery_url"]) if "discovery_url" in oidc else "",
    )
