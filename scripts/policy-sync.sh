#!/usr/bin/env bash
# Push policies/*.yaml to the control plane (POST /v1/policies → version++).
# Boot seeding is insert-if-absent by design (UI edits win on reboot); this
# is the explicit "disk is truth" operator action. In-flight runs keep their
# frozen policy snapshot — only future runs pick the new version up.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
export FLUIDBOX_API_URL=${FLUIDBOX_API_URL:-http://127.0.0.1:8787}
export FLUIDBOX_ADMIN_TOKEN
for f in policies/*.yaml; do
  python3 - "$f" <<'EOF'
import json, os, pathlib, sys, urllib.request

path = pathlib.Path(sys.argv[1])
yaml = path.read_text()
name = next(l.split(":", 1)[1].strip() for l in yaml.splitlines() if l.startswith("name:"))
req = urllib.request.Request(
    os.environ["FLUIDBOX_API_URL"] + "/v1/policies",
    data=json.dumps({"name": name, "yaml": yaml}).encode(),
    headers={
        "authorization": "Bearer " + os.environ["FLUIDBOX_ADMIN_TOKEN"],
        "content-type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(req) as r:
    policy = json.load(r)["policy"]
print(f"  ✓ {name} → version {policy['version']}")
EOF
done
