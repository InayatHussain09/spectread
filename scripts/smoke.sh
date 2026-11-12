#!/usr/bin/env bash
# Offline wiring test. No network, no AD, no credentials.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0; fail=0; failed=()

for c in $(python3 -c 'import main; print("\n".join(sorted(main.COMMANDS)))'); do
  if ./main.py "$c" -h >/dev/null 2>&1; then
    printf '  ok    %s\n' "$c"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n' "$c"; failed+=("$c"); fail=$((fail + 1))
  fi
done

echo
echo "  parse: $pass ok / $fail fail"
[ "$fail" -eq 0 ] || { printf '  broken: %s\n' "${failed[*]}"; exit 1; }

echo
echo "  store round-trip"
tmp=$(mktemp -d)
python3 - "$tmp" <<'PY'
import sys, os
sys.path.insert(0, os.getcwd())
from core.store import Store
s = Store(os.path.join(sys.argv[1], "t.db"))
s.add_host("10.0.0.1", "dc01", [88, 389], dc=True)
s.add_user("user01", "lab.local", "CN=user01", admincount=True)
s.set_policy("lab.local", 5, 1800, 1800, 8, 24, 0)
s.add_cred("lab.local", "user01", "x", "password", "test", valid=True)
s.add_ace("user10", "GenericAll", "HELPDESK")
s.add_adcs("VulnTemplate", "ESC1", True, "flags=0x10")
s.add_owned("user01", "test")
s.add_machine("SPECTRE01$", "p", "CN=SPECTRE01")
s.add_dpapi("user01", "credman", "blob", "user:pass")
s.add_finding("high", "test finding", "evidence", host="10.0.0.1")
s.log("test", "action", "target", "result")
assert s.summary()["hosts"] == 1
assert s.summary()["machines"] == 1
assert s.summary()["dpapi_secrets"] == 1
assert s.owned() == ["user01"]
print("  ok    insert + read")
s.close()
PY
[ $? -eq 0 ] || fail=$((fail + 1))

echo "  report generation"
python3 - "$tmp" <<'PY'
import sys, os
sys.path.insert(0, os.getcwd())
from core.store import Store
from core.report import _markdown, _json
db = os.path.join(sys.argv[1], "t.db")
s = Store(db)
md = os.path.join(sys.argv[1], "r.md")
js = os.path.join(sys.argv[1], "r.json")
_markdown(s, md); _json(s, js)
body = open(md).read()
assert "test finding" in body and "DPAPI secrets" in body
assert "SPECTRE01$" in body
print("  ok    markdown + json")
s.close()
PY
[ $? -eq 0 ] || fail=$((fail + 1))

rm -rf "$tmp"
echo
[ "$fail" -eq 0 ] && echo "  SMOKE PASS" || echo "  SMOKE FAIL ($fail)"
exit "$fail"
