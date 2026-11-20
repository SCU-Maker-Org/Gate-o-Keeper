"""Gate-o-Keeper club door access service."""


def main():
    import argparse
    import logging
    from pathlib import Path

    from waitress import serve

    from .config import load
    from .web import create_app

    parser = argparse.ArgumentParser(description="启动社团门禁服务")
    parser.add_argument("--config", type=Path, default=Path("gate.toml"))
    parser.add_argument("--listen", default="127.0.0.1:8000")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        app = create_app(load(args.config))
    except (OSError, KeyError, ValueError, ImportError, AttributeError) as error:
        parser.exit(2, f"配置加载失败：{error}\n")
    permissions = app.extensions["gate_permissions"]
    thread = permissions.start()
    try:
        serve(app, listen=args.listen)
    finally:
        permissions.stop()
        thread.join(timeout=7)
