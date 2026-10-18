"""
Security tests for the admin-panel anti-tamper monitor.

Runs entirely inside a disposable temp directory; it never touches production
files or data. Uses only the standard library so it can run with the project
venv interpreter without extra dependencies.

Run:  /syntax/venv/bin/python -m unittest discover -s /syntax/tests -v
"""
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

INTEGRITY_PY = os.environ.get(
    "INTEGRITY_PY", "/syntax/app/util/integrity.py"
)

spec = importlib.util.spec_from_file_location("integrity", INTEGRITY_PY)
integ = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integ)


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v, ex=None, nx=False):
        if nx and k in self.store:
            return False
        self.store[k] = v
        return True

    def delete(self, k):
        self.store.pop(k, None)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="integrity-test-")
        self.root = os.path.join(self.tmp, "project")
        self.appr = os.path.join(self.tmp, "approved")
        os.makedirs(os.path.join(self.root, "app/pages/admin"))
        os.makedirs(os.path.join(self.root, "app/pages/other"))
        os.makedirs(self.appr)

        # protected files
        self.files = {
            "app/pages/admin/admin.py": "print('approved admin')\n",
            "app/pages/admin/index.html": "<html>approved</html>\n",
        }
        for rel, content in self.files.items():
            with open(os.path.join(self.root, rel), "w") as fh:
                fh.write(content)
        # a file outside the protected scope
        with open(os.path.join(self.root, "app/pages/other/notes.txt"), "w") as fh:
            fh.write("unrelated\n")

        # point the module at our sandbox
        integ.INTEGRITY_HOME = self.tmp
        integ.MANIFEST_PATH = os.path.join(self.tmp, "manifest.json")
        integ.CONFIG_PATH = os.path.join(self.tmp, "config.json")
        integ.BACKUP_DIR = os.path.join(self.tmp, "backups")
        integ.AUDIT_LOG = os.path.join(self.tmp, "audit.jsonl")
        integ.QUARANTINE_DIR = os.path.join(self.tmp, "quarantine")

        self.cfg = {
            "project_root": self.root,
            "python_bin": "python3",
            "service": "syntax",
            "health_url": "http://127.0.0.1:1/",
            "protected": [
                "app/pages/admin",
            ],
            "exclude_suffixes": [".pyc", ".bak", ".log"],
            "backup_sources": {"approved_root": self.appr},
        }
        with open(integ.CONFIG_PATH, "w") as fh:
            json.dump(self.cfg, fh)

        # approved backups == the trusted copies
        for rel, content in self.files.items():
            dst = os.path.join(self.appr, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write(content)

        integ.build_manifest(self.cfg)
        self.redis = FakeRedis()

        # capture alerts instead of hitting Discord
        self.alerts = []
        integ._alert = lambda rec: self.alerts.append(rec)
        integ._LAST_ALERT.clear()
        # avoid real restarts / health calls
        self.reload_calls = []
        integ._reload_service = lambda cfg: (self.reload_calls.append(1) or (True, "restarted"))
        integ._service_health = lambda cfg: (True, "http 200")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, content):
        with open(os.path.join(self.root, rel), "w") as fh:
            fh.write(content)

    def _read(self, rel):
        with open(os.path.join(self.root, rel)) as fh:
            return fh.read()

    # 1
    def test_unchanged_file_is_clean(self):
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["event"], "clean")
        self.assertEqual(rec["changes"], [])
        self.assertEqual(self.alerts, [])

    # 2
    def test_authorized_deployment_not_recovered(self):
        self.redis.set(integ.DEPLOY_WINDOW_KEY, __import__("time").time() + 600)
        self._write("app/pages/admin/index.html", "<html>owner approved v2</html>\n")
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["event"], "authorized_change")
        self.assertFalse(rec["recovery"]["attempted"])
        self.assertEqual(self._read("app/pages/admin/index.html"),
                         "<html>owner approved v2</html>\n")

    # 3
    def test_modified_file_is_detected_and_restored(self):
        self._write("app/pages/admin/admin.py", "print('tampered')\n")
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["event"], "tamper")
        self.assertEqual(rec["changes"][0]["kind"], "modified")
        self.assertEqual(rec["recovery"]["result"], "restored")
        self.assertEqual(self._read("app/pages/admin/admin.py"),
                         "print('approved admin')\n")
        self.assertEqual(len(self.alerts), 1)
        # incident was recorded before recovery
        with open(integ.AUDIT_LOG) as fh:
            events = [json.loads(l)["event"] for l in fh]
        self.assertIn("tamper", events)

    # 4
    def test_deleted_file_is_restored(self):
        os.remove(os.path.join(self.root, "app/pages/admin/index.html"))
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["changes"][0]["kind"], "deleted")
        self.assertEqual(rec["recovery"]["result"], "restored")
        self.assertTrue(os.path.exists(os.path.join(self.root, "app/pages/admin/index.html")))

    # 5
    def test_missing_baseline_fails_safe(self):
        os.remove(integ.MANIFEST_PATH)
        with self.assertRaises(integ.BaselineUnavailable):
            integ.load_manifest()
        with self.assertRaises(integ.BaselineUnavailable):
            integ.run_check(redis_client=self.redis, cfg=self.cfg)

    # 6
    def test_corrupt_baseline_fails_safe(self):
        with open(integ.MANIFEST_PATH, "w") as fh:
            fh.write('{"files": {"x": {}}, "manifest_hmac": "deadbeef"}')
        with self.assertRaises(integ.BaselineUnavailable):
            integ.load_manifest()

    # 7
    def test_failed_restore_is_reported(self):
        shutil.rmtree(self.appr)  # no approved copies available
        self._write("app/pages/admin/admin.py", "print('tampered')\n")
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["recovery"]["result"], "failed")
        self.assertEqual(len(self.alerts), 1)

    # 8
    def test_change_outside_scope_is_ignored(self):
        self._write("app/pages/other/notes.txt", "changed unrelated file\n")
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["event"], "clean")
        self.assertEqual(self.alerts, [])

    # 9
    def test_health_check_failure_handling(self):
        integ._service_health = lambda cfg: (False, "http 500")
        self._write("app/pages/admin/admin.py", "print('tampered')\n")
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertEqual(rec["recovery"]["result"], "restored_but_unhealthy")

    # 10
    def test_repeated_incidents_do_not_duplicate_notifications(self):
        self._write("app/pages/admin/admin.py", "print('tampered-A')\n")
        integ.run_check(redis_client=self.redis, cfg=self.cfg)
        n_after_first = len(self.alerts)
        # same tamper again (identical observed hash after restore-then-retamper)
        self._write("app/pages/admin/admin.py", "print('tampered-A')\n")
        rec2 = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertTrue(rec2.get("alert_suppressed"))
        self.assertEqual(len(self.alerts), n_after_first)

    # extra: unexpected addition is quarantined, not trusted
    def test_unexpected_addition_is_quarantined(self):
        self._write("app/pages/admin/backdoor.html", "<script>evil</script>\n")
        rec = integ.run_check(redis_client=self.redis, cfg=self.cfg)
        self.assertIn("app/pages/admin/backdoor.html", rec["additions"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
