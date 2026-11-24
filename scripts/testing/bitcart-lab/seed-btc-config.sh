#!/bin/sh
# Container-side helper that seeds Electrum /data/config with auto_connect=false.
# Mirrors arkfile-bitcart/scripts/seed-btc-config.sh so wallet subscriptions
# never silently fail over to random public Electrum peers and BTC_ONESERVER=true
# does not trigger Electrum's auto_connect conflict.

set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ ! -r /proc/self/uid_map ]; then
    echo "[X] Cannot read /proc/self/uid_map; aborting." >&2
    exit 1
fi

if awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { found = 1 } END { exit(found ? 0 : 1) }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

python3 - <<'PY'
import json
import os
import pwd

cfg_path = "/data/config"
tmp_path = "/data/config.tmp"
data = {}

if os.path.exists(cfg_path):
    with open(cfg_path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw:
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise SystemExit("[X] Existing /data/config is not a JSON object.")
        data = loaded

data["auto_connect"] = False

with open(tmp_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")

os.chmod(tmp_path, 0o600)
try:
    pw = pwd.getpwnam("electrum")
    if os.geteuid() == 0:
        os.chown(tmp_path, pw.pw_uid, pw.pw_gid)
except KeyError:
    pass

os.replace(tmp_path, cfg_path)
print("[OK] Seeded /data/config with auto_connect=false.")
PY
