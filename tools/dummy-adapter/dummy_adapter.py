#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "paho-mqtt>=2.0",
#   "requests>=2.31",
# ]
# ///
"""
Simulated Smart Locker Adapter (Dummy Adapter).

Implements the HTTP bootstrap + MQTTS mTLS protocol using adapterId alone
(1:1 lock binding is resolved server-side from adapterId):
  1. POST /api/adapter/register -> GET /api/adapter/status until approved
  2. Connects to EMQX on 8883 via TLS mTLS (CA + client cert/key + token)
  3. Subscribes to adapter/<id>/cmd (QoS 2) and handles:
     - unlock        -> transitions state to unlocked, replies on /result, auto-relocks
     - query_state   -> publishes current state snapshot to /state
     - refresh_token -> persists rotated token, updates MQTT password, sends /ack
  4. Periodically reports state to adapter/<id>/state and presence to /presence
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import signal
import ssl
import subprocess
import sys
import threading
import time
from typing import Any

import paho.mqtt.client as mqtt
import requests


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_fingerprint(adapter_id: str, token: str) -> str:
    token_hash = sha256_hex(token)
    return sha256_hex(f"{adapter_id}:{token_hash}")[:16]


class AdapterStateStore:
    def __init__(self, path: pathlib.Path, adapter_id: str):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.token: str = data["token"]
            self.lock_state: str = data.get("lock_state", "locked")
        else:
            self.token = secrets.token_hex(24)
            self.lock_state = "locked"
            self._save_locked(adapter_id)

    def _save_locked(self, adapter_id: str) -> None:
        payload = {
            "adapter_id": adapter_id,
            "token": self.token,
            "lock_state": self.lock_state,
            "updated_at": int(time.time()),
        }
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, indent=2) + "\n")
        os.replace(tmp, self.path)

    def set_token(self, adapter_id: str, new_token: str) -> None:
        with self._lock:
            self.token = new_token
            self._save_locked(adapter_id)

    def set_lock_state(self, adapter_id: str, new_state: str) -> None:
        with self._lock:
            self.lock_state = new_state
            self._save_locked(adapter_id)


def parse_args() -> argparse.Namespace:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    certs_dir = repo_root / "certs"
    state_dir = pathlib.Path(__file__).resolve().parent / ".state"

    p = argparse.ArgumentParser(description="Simulated Smart Locker Dummy Adapter")
    p.add_argument("--adapter-id", default="adapter-demo", help="Adapter ID (must match cert CN)")
    p.add_argument("--backend-url", default="http://127.0.0.1:8080", help="Backend HTTP base URL")
    p.add_argument("--mqtt-host", default="127.0.0.1", help="EMQX MQTTS host")
    p.add_argument("--mqtt-port", type=int, default=8883, help="EMQX MQTTS port")
    p.add_argument("--ca-cert", type=pathlib.Path, default=certs_dir / "ca.crt")
    p.add_argument("--client-cert", type=pathlib.Path, default=certs_dir / "adapter-demo.crt")
    p.add_argument("--client-key", type=pathlib.Path, default=certs_dir / "adapter-demo.key")
    p.add_argument("--model", default="dummy-esp32-s3", help="Hardware model metadata")
    p.add_argument("--fw-version", default="0.1.0-sim", help="Firmware version metadata")
    p.add_argument("--poll-interval", type=float, default=5.0, help="Approval poll interval (sec)")
    p.add_argument(
        "--state-interval",
        type=float,
        default=None,
        help="Override periodic state report interval (sec); defaults to server stateReportPeriodSec",
    )
    p.add_argument("--relock-delay", type=float, default=5.0, help="Auto-relock delay after unlock (sec)")
    p.add_argument("--fail-unlock", action="store_true", help="Simulate hardware unlock failure")
    p.add_argument("--state-file", type=pathlib.Path, default=None, help="Override state JSON path")
    args = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.adapter_id):
        p.error("--adapter-id must match ^[A-Za-z0-9_-]{1,64}$")
    if args.state_file is None:
        args.state_file = state_dir / f"{args.adapter_id}.json"
    return args


def sign_registration_payload(
    client_key_path: pathlib.Path,
    adapter_id: str,
    token: str,
    ts: int,
) -> str:
    msg = f"locker-adapter-register:v1:{adapter_id}:{sha256_hex(token)}:{ts}".encode("utf-8")
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(client_key_path)],
        input=msg,
        capture_output=True,
        check=True,
    )
    return base64.b64encode(proc.stdout).decode("ascii")


def wait_for_approval(
    args: argparse.Namespace,
    store: AdapterStateStore,
    stop_ev: threading.Event,
) -> tuple[bool, float]:
    base = args.backend_url.rstrip("/")
    headers = {"Authorization": f"Bearer {store.token}"}
    fp = compute_fingerprint(args.adapter_id, store.token)
    default_period = float(args.state_interval) if args.state_interval is not None else 60.0

    print(f"[bootstrap] adapterId={args.adapter_id} fingerprint={fp}")

    def poll_status_once() -> tuple[str | None, float]:
        try:
            r = requests.get(f"{base}/api/adapter/status", headers=headers, timeout=10)
        except requests.RequestException as exc:
            print(f"[bootstrap] poll error: {exc}", file=sys.stderr)
            return None, default_period
        if r.status_code == 200:
            data = r.json()["data"]
            period = data.get("stateReportPeriodSec")
            effective_period = (
                float(period)
                if args.state_interval is None and isinstance(period, (int, float)) and period >= 10
                else default_period
            )
            return str(data["approvalStatus"]), effective_period
        if r.status_code == 401:
            return "__401__", default_period
        print(f"[bootstrap] status check returned {r.status_code}: {r.text}", file=sys.stderr)
        return None, default_period

    def try_register() -> str | None:
        try:
            ts = int(time.time())
            cert_pem = args.client_cert.read_text(encoding="utf-8")
            signature = sign_registration_payload(args.client_key, args.adapter_id, store.token, ts)
            reg_resp = requests.post(
                f"{base}/api/adapter/register",
                json={
                    "adapterId": args.adapter_id,
                    "token": store.token,
                    "model": args.model,
                    "fwVersion": args.fw_version,
                    "certPem": cert_pem,
                    "ts": ts,
                    "signature": signature,
                },
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, requests.RequestException) as exc:
            print(f"[bootstrap] register error: {exc}", file=sys.stderr)
            return None

        if reg_resp.status_code == 200:
            return str(reg_resp.json()["data"]["approvalStatus"])
        if reg_resp.status_code == 403:
            print(f"[bootstrap] register returned 403 ({reg_resp.text}); waiting for admin reset/approval...", file=sys.stderr)
            return "revoked"
        print(f"[bootstrap] register failed ({reg_resp.status_code}): {reg_resp.text}", file=sys.stderr)
        return None

    status = try_register()
    if status == "approved":
        _, period = poll_status_once()
        print(f"[bootstrap] already approved (stateReportPeriodSec={period}s)")
        return True, period

    if status is not None:
        print(f"[bootstrap] registered (status={status}); waiting for admin approval in Maker console...")

    while not stop_ev.is_set():
        stop_ev.wait(args.poll_interval)
        if stop_ev.is_set():
            return False, default_period
        approval, period = poll_status_once()
        if approval == "__401__":
            print("[bootstrap] adapter record missing (401); attempting re-registration...", file=sys.stderr)
            reg_status = try_register()
            if reg_status == "approved":
                _, period = poll_status_once()
                return True, period
            continue
        if approval is None:
            continue
        if approval == "approved":
            print(f"[bootstrap] approved! Proceeding to MQTTS connection (stateReportPeriodSec={period}s).")
            return True, period
        print(f"[bootstrap] still {approval} (fingerprint={fp})...")

    return False, default_period


def main() -> int:
    args = parse_args()
    for p in (args.ca_cert, args.client_cert, args.client_key):
        if not p.exists():
            print(f"[error] missing certificate file: {p}", file=sys.stderr)
            return 1

    stop_ev = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_ev.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_ev.set())

    store = AdapterStateStore(args.state_file, args.adapter_id)

    while not stop_ev.is_set():
        approved, state_interval = wait_for_approval(args, store, stop_ev)
        if not approved:
            return 0 if stop_ev.is_set() else 1

        reauth_ev = threading.Event()
        config_changed_ev = threading.Event()
        interval_lock = threading.Lock()

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=args.adapter_id,
            protocol=mqtt.MQTTv5,
        )
        client.username_pw_set(args.adapter_id, store.token)
        client.tls_set(
            ca_certs=str(args.ca_cert),
            certfile=str(args.client_cert),
            keyfile=str(args.client_key),
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        client.will_set(
            f"adapter/{args.adapter_id}/presence",
            json.dumps({"online": False}),
            qos=1,
            retain=False,
        )

        relock_timer_lock = threading.Lock()
        relock_timer: threading.Timer | None = None

        def publish_state(state_val: str, snapshot: bool, msg_id: str | None = None) -> None:
            env = {
                "v": 1,
                "msgId": msg_id or f"st_{secrets.token_hex(8)}",
                "ts": int(time.time()),
                "payload": {
                    "state": state_val,
                    "snapshot": snapshot,
                },
            }
            client.publish(f"adapter/{args.adapter_id}/state", json.dumps(env), qos=1)
            print(f"[state] adapter={args.adapter_id} state={state_val} snapshot={snapshot}")

        def schedule_relock() -> None:
            nonlocal relock_timer

            def _relock() -> None:
                if stop_ev.is_set() or reauth_ev.is_set():
                    return
                store.set_lock_state(args.adapter_id, "locked")
                publish_state("locked", snapshot=False)

            with relock_timer_lock:
                if relock_timer is not None:
                    relock_timer.cancel()
                relock_timer = threading.Timer(args.relock_delay, _relock)
                relock_timer.daemon = True
                relock_timer.start()

        def on_connect(cli: mqtt.Client, _userdata: Any, _flags: Any, rc: Any, _props: Any = None) -> None:
            if rc == 0:
                print(f"[mqtts] connected to {args.mqtt_host}:{args.mqtt_port} as {args.adapter_id}")
                cli.subscribe(f"adapter/{args.adapter_id}/cmd", qos=2)
                cli.publish(f"adapter/{args.adapter_id}/presence", json.dumps({"online": True}), qos=1)
                publish_state(store.lock_state, snapshot=True)
            else:
                print(f"[mqtts] connection rejected rc={rc}; returning to approval check", file=sys.stderr)
                reauth_ev.set()

        def on_disconnect(_cli: mqtt.Client, _userdata: Any, _flags: Any, rc: Any, _props: Any = None) -> None:
            print(f"[mqtts] disconnected rc={rc}")

        def on_message(_cli: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
            try:
                env = json.loads(msg.payload.decode("utf-8"))
                msg_id = str(env["msgId"])
                payload = env["payload"]
                cmd = payload.get("command")
            except Exception as exc:
                print(f"[mqtts] malformed command payload: {exc}", file=sys.stderr)
                return

            log_payload = (
                {**payload, "token": "<redacted>"}
                if isinstance(payload, dict) and "token" in payload
                else payload
            )
            print(f"[cmd] qos={msg.qos} msgId={msg_id} command={cmd} payload={log_payload}")

            if cmd == "unlock":
                cmd_ts = env.get("ts")
                timeout_ms = payload.get("timeoutMs", 10000)
                if (
                    not isinstance(cmd_ts, (int, float))
                    or not isinstance(timeout_ms, (int, float))
                    or timeout_ms <= 0
                ):
                    print(
                        f"[cmd] ignoring unlock with invalid ts/timeoutMs: ts={cmd_ts} timeoutMs={timeout_ms}",
                        file=sys.stderr,
                    )
                    return
                now_sec = time.time()
                max_age_sec = max(1.0, float(timeout_ms) / 1000.0)
                age_sec = now_sec - float(cmd_ts)
                if age_sec > max_age_sec or age_sec < -30.0:
                    print(
                        f"[cmd] dropping expired/skewed unlock msgId={msg_id} age={age_sec:.2f}s max={max_age_sec:.2f}s",
                        file=sys.stderr,
                    )
                    reply = {
                        "v": 1,
                        "msgId": msg_id,
                        "ts": int(now_sec),
                        "payload": {
                            "ok": False,
                            "code": "EXPIRED",
                            "message": "unlock command expired",
                        },
                    }
                    client.publish(f"adapter/{args.adapter_id}/result", json.dumps(reply), qos=1)
                    return

                if args.fail_unlock:
                    reply = {
                        "v": 1,
                        "msgId": msg_id,
                        "ts": int(time.time()),
                        "payload": {
                            "ok": False,
                            "code": "ACTUATOR_FAULT",
                            "message": "simulated actuator failure",
                        },
                    }
                    client.publish(f"adapter/{args.adapter_id}/result", json.dumps(reply), qos=1)
                    return

                store.set_lock_state(args.adapter_id, "unlocked")
                publish_state("unlocked", snapshot=False, msg_id=msg_id)
                reply = {
                    "v": 1,
                    "msgId": msg_id,
                    "ts": int(time.time()),
                    "payload": {
                        "ok": True,
                        "code": "OK",
                        "message": "door unlocked",
                    },
                }
                client.publish(f"adapter/{args.adapter_id}/result", json.dumps(reply), qos=1)
                schedule_relock()

            elif cmd == "query_state":
                publish_state(store.lock_state, snapshot=True, msg_id=msg_id)

            elif cmd == "refresh_token":
                new_token = payload.get("token")
                if isinstance(new_token, str) and len(new_token) >= 32:
                    store.set_token(args.adapter_id, new_token)
                    client.username_pw_set(args.adapter_id, new_token)
                    ack = {
                        "v": 1,
                        "msgId": msg_id,
                        "ts": int(time.time()),
                        "payload": {"command": "refresh_token"},
                    }
                    client.publish(f"adapter/{args.adapter_id}/ack", json.dumps(ack), qos=1)
                    print(
                        f"[token] rotated and persisted (new fingerprint={compute_fingerprint(args.adapter_id, new_token)})"
                    )
                else:
                    print("[token] ignoring invalid refresh_token payload", file=sys.stderr)

            elif cmd == "set_config":
                period = payload.get("stateReportPeriodSec")
                if isinstance(period, (int, float)) and 10 <= period <= 3600:
                    with interval_lock:
                        state_interval = float(period)
                    config_changed_ev.set()
                    ack = {
                        "v": 1,
                        "msgId": msg_id,
                        "ts": int(time.time()),
                        "payload": {"command": "set_config"},
                    }
                    client.publish(f"adapter/{args.adapter_id}/ack", json.dumps(ack), qos=1)
                    print(f"[config] updated stateReportPeriodSec={state_interval}s")
                else:
                    print(f"[config] ignoring invalid set_config payload: {payload}", file=sys.stderr)

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_message = on_message

        client.connect(args.mqtt_host, args.mqtt_port, keepalive=30, clean_start=True)
        client.loop_start()

        with interval_lock:
            cur_interval = state_interval
        last_report = time.monotonic()
        next_report = last_report + cur_interval
        try:
            while not stop_ev.is_set() and not reauth_ev.is_set():
                if config_changed_ev.is_set():
                    config_changed_ev.clear()
                    with interval_lock:
                        cur_interval = state_interval
                    next_report = last_report + cur_interval
                now_mono = time.monotonic()
                if now_mono >= next_report:
                    if client.is_connected():
                        publish_state(store.lock_state, snapshot=True)
                    last_report = now_mono
                    with interval_lock:
                        cur_interval = state_interval
                    next_report = last_report + cur_interval
                wait_sec = min(1.0, max(0.05, next_report - time.monotonic()))
                if config_changed_ev.wait(timeout=wait_sec):
                    continue
        finally:
            with relock_timer_lock:
                if relock_timer is not None:
                    relock_timer.cancel()
            if client.is_connected():
                client.publish(f"adapter/{args.adapter_id}/presence", json.dumps({"online": False}), qos=1)
            client.loop_stop()
            client.disconnect()

    print("[shutdown] dummy adapter stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
