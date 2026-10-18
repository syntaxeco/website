#!/usr/bin/env python3
"""
Owner-facing CLI for the admin-panel anti-tamper system.

Run as root from /syntax with the project venv:

  /syntax/venv/bin/python /syntax/tools/integrity_cli.py init          # build baseline
  /syntax/venv/bin/python /syntax/tools/integrity_cli.py check         # one manual pass
  /syntax/venv/bin/python /syntax/tools/integrity_cli.py deploy-begin --minutes 30
  /syntax/venv/bin/python /syntax/tools/integrity_cli.py deploy-end    # re-baseline
  /syntax/venv/bin/python /syntax/tools/integrity_cli.py status
  /syntax/venv/bin/python /syntax/tools/integrity_cli.py rollback <rel-path>

This never deletes users or performs retaliatory actions.
"""
import os
import sys
import json
import time
import argparse

# app/__init__.py configures a log handler at a relative path (./logs/...), so the
# process must be rooted at the project directory before importing app.
os.chdir("/syntax")
sys.path.insert(0, "/syntax")

from app.util import integrity  # noqa: E402


def _redis():
    try:
        from app.extensions import redis_controller
        return redis_controller
    except Exception:
        import redis
        return redis.Redis(host="127.0.0.1", port=6379, db=0, decode_responses=True)


def cmd_init(args):
    cfg = integrity.load_config()
    man = integrity.build_manifest(cfg)
    print(f"baseline written to {integrity.MANIFEST_PATH}")
    print(f"protected files: {len(man['files'])}")
    print(f"hmac: {man['manifest_hmac'][:16]}...")
    return 0


def cmd_check(args):
    rec = integrity.run_check(redis_client=_redis())
    print(json.dumps(rec, indent=2))
    return 0 if rec["event"] in ("clean", "authorized_change") else 1


def cmd_deploy_begin(args):
    r = _redis()
    until = time.time() + args.minutes * 60
    r.set(integrity.DEPLOY_WINDOW_KEY, until)
    print(f"authorized deploy window open for {args.minutes} min (until {until:.0f})")
    return 0


def cmd_deploy_end(args):
    """Close the window and re-baseline so the approved change becomes trusted."""
    r = _redis()
    try:
        r.delete(integrity.DEPLOY_WINDOW_KEY)
    except Exception:
        pass
    man = integrity.build_manifest()
    print(f"deploy window closed; re-baselined {len(man['files'])} files")
    return 0


def cmd_status(args):
    try:
        man = integrity.load_manifest()
        print(f"baseline OK: {len(man['files'])} files, created {man['created_at']}")
    except integrity.BaselineUnavailable as e:
        print(f"baseline UNAVAILABLE: {e}")
        return 2
    r = _redis()
    open_ = integrity.is_deploy_window_open(r)
    print(f"deploy window open: {open_}")
    return 0


def cmd_rollback(args):
    cfg = integrity.load_config()
    ok, detail = integrity.restore_file(args.path, cfg)
    print(("OK: " if ok else "FAIL: ") + detail)
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description="Syntax admin-panel integrity monitor")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("check").set_defaults(func=cmd_check)
    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("deploy-end").set_defaults(func=cmd_deploy_end)

    db = sub.add_parser("deploy-begin")
    db.add_argument("--minutes", type=int, default=30)
    db.set_defaults(func=cmd_deploy_begin)

    rb = sub.add_parser("rollback")
    rb.add_argument("path")
    rb.set_defaults(func=cmd_rollback)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
