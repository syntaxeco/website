#!/usr/bin/env bash
# Access-hardening helper for the Syntax admin panel anti-tamper system.
#
# This script does NOT change anything by default. It audits the current access
# posture and prints the exact commands to harden it. Pass --apply to make the
# reversible changes (immutable flags + strict permissions on the trusted
# baseline). It never revokes SSH/sudo access or rotates credentials on its own;
# those require an explicit, owner-authorized procedure (see the printed steps).
set -u

INTEGRITY_HOME="/root/syntax-integrity"
ADMIN_DIR="/syntax/app/pages/admin"
PROTECTED_PATHS=(
  "$INTEGRITY_HOME"
  "/syntax/app/util/integrity.py"
  "/syntax/app/pages/admin"
  "/syntax/app/pages/admin_og"
)

echo "== SSH access (authorized_keys) =="
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  echo "-- $f"
  awk '{print "   key:", substr($1,1,20)"...", $NF}' "$f"
done

echo
echo "== sudoers =="
grep -rhE '^[^#].*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^/   /' || echo "   (none)"

echo
echo "== recently modified protected files (last 7 days) =="
find "$ADMIN_DIR" "$INTEGRITY_HOME" -type f -mtime -7 2>/dev/null \
  | xargs -r ls -la --time-style=long-iso | sed 's/^/   /'

echo
echo "== secrets in source (config.py should not be world-readable) =="
ls -la /syntax/config.py | sed 's/^/   /'

echo
echo "== recommended hardening steps (owner-authorized) =="
cat <<'EOS'
   1. Restrict who can write the protected tree:
        chown -R root:root /syntax/app/pages/admin /syntax/app/pages/admin_og
        chmod -R go-w /syntax/app/pages/admin /syntax/app/pages/admin_og
   2. Make the trusted baseline + approved backups readable only by root:
        chmod 700 /root/syntax-integrity
        chmod 600 /root/syntax-integrity/manifest.json /root/syntax-integrity/integrity_config.json
   3. (Optional, strong) Immutable flags so even root must unset before editing:
        chattr +i /root/syntax-integrity/manifest.json
        # unset with: chattr -i <file>
   4. Remove any SSH key / sudo entry that is not yours (do this by hand, verify first):
        # review /root/.ssh/authorized_keys and /etc/sudoers.d/* above
   5. Rotate credentials that were ever committed to source (config.py):
        # FLASK_SESSION_KEY, SQLALCHEMY_DATABASE_URI password, Discord bot token/secret
   6. Route all approved changes through the deploy window:
        /syntax/venv/bin/python /syntax/tools/integrity_cli.py deploy-begin --minutes 30
EOS

if [ "${1:-}" = "--apply" ]; then
  echo
  echo "== applying reversible hardening =="
  chown -R root:root "$ADMIN_DIR" /syntax/app/pages/admin_og 2>/dev/null || true
  chmod -R go-w "$ADMIN_DIR" /syntax/app/pages/admin_og 2>/dev/null || true
  chmod 700 "$INTEGRITY_HOME" 2>/dev/null || true
  chmod 600 "$INTEGRITY_HOME/manifest.json" "$INTEGRITY_HOME/integrity_config.json" 2>/dev/null || true
  echo "applied. (No SSH/sudo changes were made.)"
fi
