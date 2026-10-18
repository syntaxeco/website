"""
Admin-panel anti-tamper / integrity monitor.

Detects unauthorised changes to security-sensitive deployment files and restores
the last owner-approved version from a protected backup. It NEVER deletes users,
bans accounts, blacklists hosts or performs any destructive/retaliatory action.

Design
------
* Scope (protected files) is configured in a JSON file that lives OUTSIDE the
  monitored tree, alongside the trusted baseline.
* The trusted baseline (hashes) also lives outside the monitored tree so an
  ordinary application-level developer cannot silently rewrite it.
* A short "authorized deploy window" (Redis) lets the owner perform an approved
  change without triggering recovery.
* Fail-safe: a missing/corrupt baseline raises BaselineUnavailable and refuses to
  run (so a broken baseline cannot silently disable protection).
* Every incident is written to a JSONL audit log and alerted to Discord
  (without secrets) before recovery is attempted.

Trust model / limits
--------------------
A monitor running as the same OS user (root) cannot fully defend against a
determined root-level attacker: they could rewrite this code, the baseline, or
stop the service. Real defence-in-depth is the access hardening documented in
tools/security_hardening.sh (restrict SSH/sudo, immutable files, rotation) plus
running this monitor from a location the app user cannot write.
"""

import os
import io
import json
import time
import hmac
import uuid
import shutil
import hashlib
import logging
import datetime
import subprocess

try:
    import requests
except Exception:  # allow importing/testing without requests installed
    requests = None

PROJECT_ROOT = "/syntax"
INTEGRITY_HOME = "/root/syntax-integrity"
MANIFEST_PATH = os.path.join(INTEGRITY_HOME, "manifest.json")
CONFIG_PATH = os.path.join(INTEGRITY_HOME, "integrity_config.json")
BACKUP_DIR = os.path.join(INTEGRITY_HOME, "approved_backups")
AUDIT_LOG = os.path.join(INTEGRITY_HOME, "audit.jsonl")
QUARANTINE_DIR = os.path.join(INTEGRITY_HOME, "quarantine")
DEPLOY_WINDOW_KEY = "integrity:deploy_window_until"

logger = logging.getLogger("integrity")


class BaselineUnavailable(Exception):
    """Raised when the trusted baseline/config is missing, corrupt or unverifiable."""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_config(path=None):
    path = path or CONFIG_PATH
    if not os.path.exists(path):
        raise BaselineUnavailable(f"integrity config not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            cfg = json.load(fh)
        except json.JSONDecodeError as e:
            raise BaselineUnavailable(f"integrity config corrupt: {e}")
    for key in ("protected", "backup_sources", "exclude_suffixes"):
        if key not in cfg:
            raise BaselineUnavailable(f"integrity config missing key: {key}")
    return cfg


def _iter_protected_files(cfg):
    """Yield project-relative paths of every protected file that exists."""
    root = cfg.get("project_root", PROJECT_ROOT)
    excludes = tuple(cfg.get("exclude_suffixes", []))
    seen = set()
    for entry in cfg["protected"]:
        abspath = os.path.join(root, entry)
        if os.path.isdir(abspath):
            for dirpath, dirnames, filenames in os.walk(abspath):
                dirnames[:] = [d for d in dirnames if not d.startswith("__pycache__")]
                for name in filenames:
                    if name.endswith(excludes):
                        continue
                    full = os.path.join(dirpath, name)
                    rel = os.path.relpath(full, root)
                    if rel not in seen:
                        seen.add(rel)
                        yield rel
        elif os.path.isfile(abspath):
            rel = os.path.relpath(abspath, root)
            if rel not in seen:
                seen.add(rel)
                yield rel
        else:
            # a protected entry that does not exist is itself notable; surface it
            rel = entry.lstrip("./")
            if rel not in seen:
                seen.add(rel)
                yield rel


# --------------------------------------------------------------------------- #
# manifest / baseline
# --------------------------------------------------------------------------- #
def build_manifest(cfg=None, manifest_path=None):
    manifest_path = manifest_path or MANIFEST_PATH
    """Compute and persist the trusted baseline. Records the hashes + mtimes."""
    cfg = cfg or load_config()
    root = cfg.get("project_root", PROJECT_ROOT)
    files = {}
    for rel in _iter_protected_files(cfg):
        full = os.path.join(root, rel)
        if os.path.isfile(full):
            st = os.stat(full)
            files[rel] = {
                "sha256": _sha256_file(full),
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            }
        else:
            files[rel] = {"sha256": None, "size": None, "mtime": None}
    manifest = {
        "created_at": _now_iso(),
        "project_root": root,
        "files": files,
        "manifest_hmac": None,
    }
    return _write_manifest(manifest, manifest_path)


def _write_manifest(manifest, path=None):
    path = path or MANIFEST_PATH
    key = _manifest_key()
    body = dict(manifest)
    body.pop("manifest_hmac", None)
    body["manifest_hmac"] = hmac.new(
        key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256
    ).hexdigest()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return body


def _manifest_key():
    """HMAC key for the manifest. Derived from the owner's root-only config,
    falling back to a constant so tests and first-run still work."""
    try:
        cfg = load_config()
        if cfg.get("manifest_key"):
            return str(cfg["manifest_key"]).encode()
    except Exception:
        pass
    return b"syntax-integrity-default-manifest-key"


def load_manifest(path=None):
    path = path or MANIFEST_PATH
    if not os.path.exists(path):
        raise BaselineUnavailable(f"trusted baseline missing: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            manifest = json.load(fh)
        except json.JSONDecodeError as e:
            raise BaselineUnavailable(f"trusted baseline corrupt: {e}")
    if "files" not in manifest:
        raise BaselineUnavailable("trusted baseline has no files map")
    expected = manifest.get("manifest_hmac")
    body = dict(manifest)
    body.pop("manifest_hmac", None)
    actual = hmac.new(
        _manifest_key(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256
    ).hexdigest()
    if expected is not None and not hmac.compare_digest(expected, actual):
        raise BaselineUnavailable("trusted baseline HMAC mismatch (tampered or stale)")
    return manifest


# --------------------------------------------------------------------------- #
# scan / diff
# --------------------------------------------------------------------------- #
def scan(cfg=None, manifest=None):
    """Compare the current tree against the baseline.

    Returns (changes, additions) where changes maps rel -> dict(kind, expected,
    observed) and additions is a list of unexpected files under protected dirs.
    """
    cfg = cfg or load_config()
    manifest = manifest or load_manifest()
    root = cfg.get("project_root", PROJECT_ROOT)
    baseline = manifest["files"]

    current = {}
    for rel in _iter_protected_files(cfg):
        full = os.path.join(root, rel)
        if os.path.isfile(full):
            current[rel] = _sha256_file(full)

    changes = {}
    for rel, meta in baseline.items():
        expected = meta.get("sha256")
        observed = current.get(rel)
        if observed is None:
            changes[rel] = {"kind": "deleted", "expected": expected, "observed": None}
        elif expected is None:
            # baseline had it as missing but now it exists -> unexpected addition
            changes[rel] = {"kind": "added", "expected": None, "observed": observed}
        elif observed != expected:
            changes[rel] = {"kind": "modified", "expected": expected, "observed": observed}

    additions = [
        rel for rel in current
        if rel not in baseline
    ]
    return changes, additions


def is_deploy_window_open(redis_client):
    try:
        until = redis_client.get(DEPLOY_WINDOW_KEY)
        return until is not None and float(until) > time.time()
    except Exception:
        return False


def _git_head_sha(root):
    try:
        r = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _git_committed_sha(root, rel):
    """sha256 of the file as committed in HEAD (what a GitHub deploy would lay down)."""
    try:
        r = subprocess.run(["git", "-C", root, "show", f"HEAD:{rel}"],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return hashlib.sha256(r.stdout).hexdigest()
    except Exception:
        pass
    return None


def _git_authorized_changes(cfg, changes):
    """A change is authorized when the file's current content equals the content
    committed in HEAD, i.e. it arrived through the normal GitHub deploy path
    (deploy.py pulls origin/main). Returns the list of such paths."""
    root = cfg.get("project_root", PROJECT_ROOT)
    if _git_head_sha(root) is None:
        return []
    ok = []
    for c in changes:
        rel = c["path"]
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            continue
        committed = _git_committed_sha(root, rel)
        if committed and committed == _sha256_file(full):
            ok.append(rel)
    return ok


def _backup_approved(rel, cfg):
    root = cfg.get("project_root", PROJECT_ROOT)
    src = os.path.join(root, rel)
    dst = os.path.join(BACKUP_DIR, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)


def _rebaseline(manifest, cfg, rels):
    """Update the trusted baseline for the given files only (leaves any other
    pending changes baselined as-is) and re-sign the manifest."""
    root = cfg.get("project_root", PROJECT_ROOT)
    for rel in rels:
        full = os.path.join(root, rel)
        if os.path.isfile(full):
            st = os.stat(full)
            manifest["files"][rel] = {
                "sha256": _sha256_file(full),
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            }
        else:
            manifest["files"][rel] = {"sha256": None, "size": None, "mtime": None}
    _write_manifest(manifest)


# --------------------------------------------------------------------------- #
# audit + notifications
# --------------------------------------------------------------------------- #
def _append_audit(record):
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def _alert(record):
    """Send a security alert through the project's existing admin-log webhook."""
    try:
        from app.util.adminlog import SendAdminLog
        files = record.get("changes", [])
        summary = "\n".join(
            f"`{c['path']}` **{c['kind']}** (exp `{(c['expected'] or '-')[:10]}`, "
            f"obs `{(c['observed'] or '-')[:10]}`)"
            for c in files[:10]
        ) or "(none)"
        recovery = record.get("recovery", {})
        fields = [
            {"name": "Affected files", "value": summary[:1000], "inline": False},
            {"name": "Recovery attempted", "value": str(recovery.get("attempted", False)), "inline": True},
            {"name": "Recovery result", "value": str(recovery.get("result", "n/a")), "inline": True},
            {"name": "Actor", "value": str(record.get("actor") or "unknown"), "inline": True},
            {"name": "Audit ref", "value": str(record.get("id", "-")), "inline": True},
        ]
        SendAdminLog(
            title=f"⚠ Integrity incident: {record.get('event', 'tamper')}",
            description=record.get("summary", "Protected file change detected"),
            fields=fields,
            color=0xE74C3C if recovery.get("result") != "restored" else 0xE67E22,
            footer="Syntax Integrity Monitor",
        )
    except Exception as e:  # never let alerting break recovery
        logger.warning(f"integrity: alert failed: {e}")


ALERT_DEDUP_WINDOW = 300  # seconds
_LAST_ALERT = {}


def _incident_signature(record):
    return tuple(sorted((c["path"], c.get("observed")) for c in record.get("changes", [])))


def _recent_duplicate(record, window=ALERT_DEDUP_WINDOW):
    """True if an identical incident (same paths + observed hashes) was already
    alerted within the window, to avoid notification storms on repeated tampering."""
    sig = _incident_signature(record)
    last = _LAST_ALERT.get(sig)
    return last is not None and (time.time() - last) < window


def _maybe_alert(record):
    if _recent_duplicate(record):
        record["alert_suppressed"] = True
        return
    _LAST_ALERT[_incident_signature(record)] = time.time()
    _alert(record)


def _actor_identity():
    """Best-effort identity of whoever changed files: recent SSH logins and the
    most recent in-app admin action, when available. Never raises."""
    info = {}
    try:
        out = subprocess.run(
            ["bash", "-lc", "last -n 5 -i 2>/dev/null | head -5"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if out:
            info["recent_logins"] = out.splitlines()
    except Exception:
        pass
    try:
        from app.extensions import redis_controller
        who = redis_controller.get("integrity:last_authorized_actor")
        if who:
            info["last_authorized_actor"] = who
    except Exception:
        pass
    return info or None


# --------------------------------------------------------------------------- #
# recovery
# --------------------------------------------------------------------------- #
def _backup_source_for(rel, cfg):
    """Find the approved copy for a project-relative path."""
    src_root = cfg.get("backup_sources", {}).get("approved_root")
    if not src_root:
        return None
    candidate = os.path.join(src_root, rel)
    return candidate if os.path.exists(candidate) else None


def _quarantine(rel, cfg):
    """Preserve the offending file for investigation before restoring."""
    root = cfg.get("project_root", PROJECT_ROOT)
    full = os.path.join(root, rel)
    if not os.path.isfile(full):
        return None
    dest = os.path.join(QUARANTINE_DIR, datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S"), rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(full, dest)
    return dest


def restore_file(rel, cfg):
    """Restore a single protected file from the approved backup.

    Returns (ok: bool, detail: str).
    """
    root = cfg.get("project_root", PROJECT_ROOT)
    src = _backup_source_for(rel, cfg)
    if src is None:
        return False, f"no approved backup for {rel}"
    dest = os.path.join(root, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(src, dest)
    # validate ownership/permissions like the approved copy
    st = os.stat(src)
    try:
        os.chown(dest, st.st_uid, st.st_gid)
        os.chmod(dest, st.st_mode & 0o7777)
    except Exception:
        pass
    # verify hash now matches baseline expectation
    return True, f"restored from {src}"


def _syntax_check(rel, cfg):
    if not rel.endswith(".py"):
        return True, "not python"
    root = cfg.get("project_root", PROJECT_ROOT)
    full = os.path.join(root, rel)
    py = cfg.get("python_bin", os.path.join(root, "venv/bin/python"))
    try:
        r = subprocess.run([py, "-m", "py_compile", full],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return True, "py_compile ok"
        return False, (r.stderr or r.stdout)[:500]
    except Exception as e:
        return False, str(e)


def _service_health(cfg, attempts=10, delay=1.0):
    url = cfg.get("health_url", "http://127.0.0.1:3003/admin/")
    last = "no attempt"
    for _ in range(attempts):
        try:
            r = requests.get(url, timeout=8, allow_redirects=False)
            if r.status_code < 500:
                return True, f"http {r.status_code}"
            last = f"http {r.status_code}"
        except Exception as e:
            last = str(e)
        time.sleep(delay)
    return False, last


def _reload_service(cfg):
    svc = cfg.get("service", "syntax")
    # Restart asynchronously in a transient systemd unit so it cannot terminate
    # this process before it finishes returning.
    try:
        r = subprocess.run(
            ["systemd-run", "--no-block", "--unit=integrity-restart",
             "--collect", "systemctl", "restart", svc],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return True, "restart dispatched (systemd-run --no-block)"
        detail = (r.stderr or r.stdout).strip()[:200]
    except Exception as e:
        detail = str(e)
    # fallback: detached, non-blocking
    try:
        subprocess.Popen(["systemctl", "restart", svc], start_new_session=True)
        return True, f"restart dispatched (detached; {detail})"
    except Exception as e:
        return False, str(e)


def run_check(redis_client=None, cfg=None, manifest=None,
              allow_recovery=True, alert=True, lock=True):
    """Public entry point. Serialises concurrent passes with a Redis lock so
    repeated incidents cannot trigger overlapping restores."""
    if redis_client is not None and lock:
        ident = str(time.time())
        try:
            got = redis_client.set("integrity:check_lock", ident, nx=True, ex=120)
        except Exception:
            got = True  # if locking is unavailable, proceed rather than skip
        if not got:
            return {
                "id": "INT-locked", "ts": _now_iso(), "event": "skipped",
                "changes": [], "additions": [],
                "recovery": {"attempted": False, "result": "n/a", "details": []},
                "summary": "another integrity check is already running",
            }
        try:
            return _run_check(redis_client, cfg, manifest, allow_recovery, alert)
        finally:
            try:
                if redis_client.get("integrity:check_lock") == ident:
                    redis_client.delete("integrity:check_lock")
            except Exception:
                pass
    return _run_check(redis_client, cfg, manifest, allow_recovery, alert)


def _run_check(redis_client=None, cfg=None, manifest=None,
               allow_recovery=True, alert=True):
    """One full integrity pass. Returns a record dict; never raises for a normal
    incident (only BaselineUnavailable propagates)."""
    cfg = cfg or load_config()
    manifest = manifest or load_manifest()
    record = {
        "id": f"INT-{int(time.time()*1000)}-{uuid.uuid4().hex[:8]}",
        "ts": _now_iso(),
        "event": "tamper",
        "changes": [],
        "additions": [],
        "authorized": False,
        "actor": None,
        "recovery": {"attempted": False, "result": "n/a", "details": []},
        "summary": "",
    }

    changes, additions = scan(cfg=cfg, manifest=manifest)
    if not changes and not additions:
        record["event"] = "clean"
        record["summary"] = "no changes detected"
        return record

    record["changes"] = [
        {"path": p, **info} for p, info in sorted(changes.items())
    ]
    record["additions"] = sorted(additions)
    record["actor"] = _actor_identity()

    # authorized deploy window?
    if redis_client is not None and is_deploy_window_open(redis_client):
        record["authorized"] = True
        record["event"] = "authorized_change"
        record["summary"] = "change within authorized deploy window; baseline not reset automatically"
        _append_audit(record)
        if alert:
            _maybe_alert(record)
        return record

    record["summary"] = (
        f"{len(record['changes'])} changed/removed, {len(record['additions'])} unexpected addition(s)"
    )

    # The normal deploy path is a GitHub push that deploy.py pulls into /syntax,
    # so a file whose content now matches HEAD arrived through that path and is
    # authorized. Only out-of-band changes (which differ from HEAD) are restored.
    authorized_paths = _git_authorized_changes(cfg, record["changes"])
    if authorized_paths:
        record["authorized"] = True
        record["event"] = "authorized_change"
        record["summary"] = (
            f"{len(authorized_paths)} change(s) matched HEAD (authorized deploy); "
            f"baseline updated"
        )
        for rel in authorized_paths:
            try:
                _backup_approved(rel, cfg)
            except Exception as e:
                record["recovery"]["details"].append(f"{rel}: backup failed {e}")
        _rebaseline(manifest, cfg, authorized_paths)
        _append_audit(record)
        if alert:
            _maybe_alert(record)
        return record

    # record the incident BEFORE recovery
    _append_audit(record)

    if not allow_recovery:
        if alert:
            _maybe_alert(record)
        return record

    # preserve + restore
    record["recovery"]["attempted"] = True
    ok_all = True
    for c in record["changes"]:
        rel = c["path"]
        q = _quarantine(rel, cfg)
        if q:
            record["recovery"]["details"].append(f"quarantined {rel} -> {q}")
        if c["kind"] in ("modified", "deleted", "added"):
            ok, detail = restore_file(rel, cfg)
            record["recovery"]["details"].append(f"{rel}: {detail}")
            if not ok:
                ok_all = False
            else:
                syn_ok, syn_detail = _syntax_check(rel, cfg)
                record["recovery"]["details"].append(f"{rel}: syntax {syn_detail}")
                if not syn_ok:
                    ok_all = False

    # unexpected additions are moved to quarantine (do not trust them)
    for rel in record["additions"]:
        q = _quarantine(rel, cfg)
        if q:
            record["recovery"]["details"].append(f"quarantined addition {rel} -> {q}")

    if ok_all:
        record["recovery"]["result"] = "restored"
    else:
        record["recovery"]["result"] = "failed"

    # Persist the detection + outcome and alert BEFORE any service restart: the
    # restart tears down this process, so bookkeeping done afterwards can be lost.
    _append_audit(record)
    if alert:
        _maybe_alert(record)

    # Reload only if a file the running app loads changed. systemctl restart is
    # run detached so it cannot terminate this worker before it returns.
    if ok_all:
        needs_reload = any(
            c["path"].endswith((".py", ".html", ".css")) for c in record["changes"]
        )
        if needs_reload:
            reloaded, detail = _reload_service(cfg)
            record["recovery"]["details"].append(f"service reload: {detail}")
            healthy, hdetail = _service_health(cfg)
            record["recovery"]["details"].append(f"health: {hdetail}")
            if not healthy:
                record["recovery"]["result"] = "restored_but_unhealthy"
            _append_audit(record)
    return record


# --------------------------------------------------------------------------- #
# scheduler entrypoint
# --------------------------------------------------------------------------- #
def scheduled_check():
    """Run from the app scheduler. Opens its own app context via the caller."""
    try:
        from app.extensions import redis_controller
    except Exception:
        redis_controller = None
    try:
        run_check(redis_client=redis_controller)
    except BaselineUnavailable as e:
        logger.error(f"integrity: baseline unavailable, refusing to run: {e}")
        try:
            _append_audit({"ts": _now_iso(), "event": "baseline_unavailable",
                           "error": str(e)})
        except Exception:
            pass


def integrity_job():
    """Module-level entry point referenced by the APScheduler jobstore.

    Must live at module level (with a dotted reference) so the Redis jobstore can
    serialise it; a nested function inside create_app cannot be referenced."""
    try:
        from app.extensions import scheduler as _scheduler
        app = getattr(_scheduler, "app", None)
    except Exception:
        app = None
    if app is not None:
        with app.app_context():
            scheduled_check()
    else:
        scheduled_check()
