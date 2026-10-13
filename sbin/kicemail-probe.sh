#!/bin/bash
# kicemail-Watchdog-Probe: kompakter Zustand der KI-Mailpipeline (fuer das Gate)
echo "MIL=$(systemctl is-active kicemail-milter)"
echo "PFX=$(systemctl is-active postfix)"
echo "NR=$(systemctl show kicemail-milter -p NRestarts --value 2>/dev/null)"
echo "Q=$(mailq 2>/dev/null | grep -cE '^[0-9A-F]{9,12}[*:]')"
echo "API=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:4000/v1/models 2>/dev/null)"
python3 - <<'PY'
import json, time, os
p = "/var/log/kicemail/kiclass.log"
now = time.time()
err = tmo = rc = 0
try:
    f = open(p, encoding="utf-8", errors="replace")
    f.seek(max(0, os.path.getsize(p) - 2000000))
    for line in f:
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if now - o.get("ts", 0) > 1800:
            continue
        rc += 1
        w = o.get("why", "")
        if w == "KI-Timeout":
            tmo += 1
            err += 1
        elif o.get("act") == "none" and not o.get("class"):
            err += 1
except OSError:
    pass
print("ERR=%d\nTMO=%d\nRC=%d" % (err, tmo, rc))
PY
echo "DF=$(df --output=pcent /var 2>/dev/null | tail -1 | tr -dc 0-9)"
