import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime
from importlib import import_module
from threading import Lock
from urllib.parse import urlsplit

from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import OAuth
from flask import (
    Flask,
    abort,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from joserfc.errors import JoseError
from requests import RequestException

from .config import Settings
from .hardware import DoorRelay, InvalidScan, RelayResult, SimulatedRelay
from .permissions import (
    AuthentikDirectory,
    DirectoryUnavailable,
    HttpDirectory,
    PermissionSource,
)
from .service import Permissions
from .store import Denied, Store

MEMBER_COOKIE = "__Host-gate-member"
VISIT_ID = re.compile(r"[a-f0-9]{64}")


def create_app(
    settings: Settings,
    *,
    relay: DoorRelay | None = None,
    source: PermissionSource | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.secret,
        SESSION_COOKIE_NAME="__Host-gate-flow",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        TRUSTED_HOSTS=[urlsplit(settings.origin).hostname],
        MAX_CONTENT_LENGTH=8192,
    )
    # A different authority or door mapping must not inherit live permissions or pending visits.
    namespace = json.dumps(
        [
            settings.issuer,
            settings.client_id,
            settings.discovery_url,
            settings.relay_factory,
            settings.permission_backend,
            settings.permission_url,
            settings.group,
            settings.lookup_claim,
            {door: verifier.binding for door, verifier in settings.doors.items()},
        ],
        sort_keys=True,
    )
    fingerprint = hmac.new(
        settings.secret.encode(), namespace.encode(), hashlib.sha256
    ).hexdigest()
    store = Store(settings.database, settings.policy, fingerprint)
    if source is None:
        if settings.permission_backend == "authentik":
            source = AuthentikDirectory(
                settings.permission_url, settings.api_token, settings.group
            )
        else:
            source = HttpDirectory(settings.permission_url, settings.api_token)
    permissions = Permissions(store, source)
    if relay is None and settings.relay_factory:
        module, factory = settings.relay_factory.split(":", 1)
        relay = getattr(import_module(module), factory)()
        if not isinstance(relay, DoorRelay):
            raise ValueError("继电器工厂必须返回 DoorRelay 实例")
    relay = relay if relay is not None else SimulatedRelay()
    app.extensions.update(gate_store=store, gate_permissions=permissions)
    client = OAuth(app).register(
        "identity",
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        server_metadata_url=settings.discovery_url
        or settings.issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={
            "scope": settings.scope,
            "code_challenge_method": "S256",
            "default_timeout": 5,
        },
    )

    door_locks = {door: Lock() for door in settings.doors}

    def token():
        return request.cookies.get(MEMBER_COOKIE, "")

    def set_member(response, value, expiry):
        response.set_cookie(
            MEMBER_COOKIE,
            value,
            expires=datetime.fromtimestamp(expiry, UTC),
            secure=True,
            httponly=True,
            samesite="Lax",
            path="/",
        )

    def page(message="", status=200, **context):
        csrf = session.get("csrf")
        if not csrf:
            csrf = session["csrf"] = secrets.token_urlsafe(32)
        return make_response(
            render_template(
                "gate.html",
                message=message,
                csrf=csrf,
                member=store.member(token()),
                simulated=isinstance(relay, SimulatedRelay),
                **context,
            ),
            status,
        )

    @app.after_request
    def privacy(response):
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Referrer-Policy": "strict-origin",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-Robots-Tag": "noindex, nofollow",
                "Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            }
        )
        return response

    @app.before_request
    def protect_forms():
        if request.method == "POST" and request.endpoint != "webhook":
            csrf = session.get("csrf")
            origin = request.headers.get("Origin")
            if (
                (origin and origin != settings.origin)
                or not csrf
                or not hmac.compare_digest(
                    csrf.encode(), request.form.get("csrf", "").encode()
                )
            ):
                abort(403)

    @app.errorhandler(Denied)
    def denied(exc):
        if request.endpoint == "unlock":
            return pending_or_home(request.view_args["visit_id"], str(exc), 403)
        return page(str(exc), 403)

    @app.get("/")
    def home():
        return page()

    @app.get("/d/<door>")
    def scan(door):
        verifier = settings.doors.get(door)
        if verifier is None:
            abort(404)
        try:
            if any(len(values) != 1 for _, values in request.args.lists()):
                raise InvalidScan
            proof = verifier.verify(request.args)
        except InvalidScan:
            return page("贴纸验证失败，请重新扫描门口贴纸。", 400)
        payload = json.dumps([door, proof.tag, proof.counter]).encode()
        visit_id = hmac.new(
            settings.secret.encode(), b"visit:" + payload, hashlib.sha256
        ).hexdigest()
        store.register_scan(door, proof, visit_id)
        # A forwarded review URL always requires an explicit member confirmation.
        # Only a direct, top-level, user-activated navigation qualifies for automatic POST.
        direct = (
            request.headers.get("Sec-Fetch-Site") == "none"
            and request.headers.get("Sec-Fetch-Mode") == "navigate"
            and request.headers.get("Sec-Fetch-User") == "?1"
        )
        return visit_page(visit_id, auto=direct)

    def pending_or_home(visit_id, message, status):
        if visit_id:
            try:
                return visit_page(visit_id, message=message, status=status)
            except Denied:
                pass
        return page(message, status)

    def visit_page(visit_id, *, auto=False, message="", status=200):
        row = store.visit(visit_id)
        return page(
            message=message,
            status=status,
            visit_id=visit_id,
            door=row["door"],
            auto=auto,
            share_url=settings.origin + url_for("review", visit_id=visit_id),
        )

    @app.get("/v/<visit_id>")
    def review(visit_id):
        return visit_page(visit_id)

    @app.post("/v/<visit_id>/open")
    def unlock(visit_id):
        door = store.visit(visit_id)["door"]
        with door_locks[door]:
            attempt = store.claim(visit_id, token())
            return dispatch(attempt)

    def dispatch(attempt):
        try:
            result = relay.unlock(attempt.door, attempt.id)
            if not isinstance(result, RelayResult):
                raise TypeError("Unexpected device response")
        except Exception:  # noqa: BLE001 -- adapter may have sent the command before failing
            app.logger.warning("继电器未确认指令 %s", attempt.id)
            store.finish_attempt(attempt, "unknown", token())
            return page(
                "未收到设备确认，门锁状态未知。请检查门锁状态，必要时重新扫描。", 502
            )
        expiry = store.finish_attempt(attempt, result.value, token())
        message = (
            "模拟开门完成，本次扫描已使用。"
            if result == RelayResult.SIMULATED
            else "门锁控制器已确认开门。"
        )
        response = page(message, result_title="开门结果")
        if expiry is not None:
            set_member(response, token(), expiry)
        return response

    @app.get("/login")
    def login():
        visit_id = request.args.get("visit", "")
        session["return_visit"] = visit_id if VISIT_ID.fullmatch(visit_id) else ""
        try:
            if client.load_server_metadata().get("issuer") != settings.issuer:
                raise ValueError("OIDC discovery issuer mismatch")
            return client.authorize_redirect(settings.origin + "/auth/callback")
        except (AuthlibBaseError, RequestException, RuntimeError, ValueError, KeyError):
            return pending_or_home(visit_id, "暂时无法连接统一认证，请稍后重试。", 503)

    @app.get("/auth/callback")
    def callback():
        try:
            tokens = client.authorize_access_token(
                claims_options={
                    "iss": {"essential": True, "value": settings.issuer},
                    "aud": {"essential": True, "value": settings.client_id},
                }
            )
            if not tokens.get("id_token"):
                raise ValueError
            claims = tokens["userinfo"]
            subject = claims["sub"]
            key = claims[settings.lookup_claim]
            if (
                not isinstance(subject, str)
                or not 0 < len(subject) <= 255
                or type(key) not in {int, str}
                or not 0 < len(str(key)) <= 255
            ):
                raise ValueError
        except (
            AuthlibBaseError,
            JoseError,
            RequestException,
            KeyError,
            ValueError,
            TypeError,
            RuntimeError,
        ):
            return pending_or_home(
                session.get("return_visit"), "登录验证失败，请重新发起登录。", 401
            )
        target = session.get("return_visit")
        try:
            issued = permissions.check(subject, str(key))
        except DirectoryUnavailable:
            return pending_or_home(target, "权限源暂不可用，暂时无法建立新会话。", 503)
        if not issued:
            return pending_or_home(
                target, "该账号未取得开门权限，或权限正在变更，请重新登录核实。", 403
            )
        store.logout(token())
        session.clear()
        response = redirect(
            url_for("review", visit_id=target) if target else url_for("home"), 303
        )
        set_member(response, *issued)
        return response

    @app.post("/logout")
    def logout():
        store.logout(token())
        session.clear()
        response = redirect(url_for("home"), 303)
        response.delete_cookie(
            MEMBER_COOKIE, secure=True, httponly=True, samesite="Lax"
        )
        return response

    @app.post("/webhooks/permissions")
    def webhook():
        if not hmac.compare_digest(
            request.headers.get("Authorization", "").encode(),
            ("Bearer " + settings.webhook_secret).encode(),
        ):
            abort(401)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400)
        event, subject = data.get("event"), data.get("subject")
        if event == "refresh" and subject is None:
            permissions.wakeup.set()
            return "", 202
        if not isinstance(subject, str) or not 0 < len(subject) <= 255:
            abort(400)
        if event == "revoke":
            store.revoke(subject)
        elif event == "refresh":
            try:
                permissions.check(subject)
            except DirectoryUnavailable:
                return "", 503
        else:
            abort(400)
        return "", 204

    return app
