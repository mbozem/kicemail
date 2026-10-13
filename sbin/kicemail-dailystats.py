#!/usr/bin/env python3
# kicemail-Tagesstatistik (letzte 24 h) -kompakt fuer den taeglichen Report
import json, time, os, glob, subprocess, collections

now = time.time()
cutoff = now - 86400
cnt = collections.Counter()
lats = []
total = err = tmo = mis = misziel = sugg = att = wl = lowconf = 0
mistop = collections.Counter()
try:
    paths = ["/var/log/kicemail/kiclass.log"] + sorted(glob.glob("/var/log/kicemail/kiclass.log.*"))
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                ts = o.get("ts", 0)
                if ts < cutoff or ts > now + 3600:
                    continue
                if "note" in o:
                    continue
                total += 1
                cnt[o.get("class", "?")] += 1
                if o.get("why") == "KI-Timeout":
                    tmo += 1; err += 1
                elif o.get("act") == "none" and not o.get("class"):
                    err += 1
                if o.get("mis"):
                    mis += 1
                    if "->" in o.get("mis", ""):
                        misziel += 1
                        mistop[o.get("mis", "").split("->")[0].strip()] += 1
                if o.get("sugg_cc"):
                    sugg += 1
                if o.get("att"):
                    att += 1
                if o.get("wl"):
                    wl += 1
                if o.get("lowconf"):
                    lowconf += 1
                l = o.get("lat_ms")
                if isinstance(l, (int, float)):
                    lats.append(l)
except OSError as e:
    print("LOGFEHLER", e)

print("GESAMT", total)
for k, v in cnt.most_common(8):
    print("KLASSE", k, v)
if lats:
    lats.sort()
    print("LATENZ avg=%dms p50=%dms p95=%dms n=%d" %
          (sum(lats) / len(lats), lats[len(lats) // 2],
           lats[int(len(lats) * 0.95)] if len(lats) > 1 else lats[0], len(lats)))
print("FEHLER", err, "davon TIMEOUT", tmo)
print("MISADRESSED", mis, "davon MIT ZIEL", misziel)
for k, v in mistop.most_common(4):
    print("MISTOP", k, v)
print("SUGG_CC", sugg, "ATTACH", att, "LOWCONF", lowconf, "WHITELISTED", wl)
try:
    d = subprocess.run(["du", "-sm", "/var/lib/kicemail/archive"],
                       capture_output=True, text=True, timeout=10).stdout.split()
    print("ARCHIV_MB", d[0] if d else "?")
except Exception:
    pass
try:
    q = subprocess.run(["mailq"], capture_output=True, text=True, timeout=15)
    print("QUEUE", (q.stdout.splitlines() or ["?"])[-1])
except Exception:
    pass
for u in ("kicemail-milter", "postfix", "amavis", "clamav-daemon"):
    try:
        s = subprocess.run(["systemctl", "is-active", u],
                           capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        s = "?"
    print("DIENST", u, s)
try:
    api = subprocess.run(
        ["curl", "-s", "-m", "6", "-o", "/dev/null", "-w", "%{http_code}",
         "http://127.0.0.1:4000/v1/models"],
        capture_output=True, text=True, timeout=10)
    print("MODELLHOST", api.stdout.strip() or "?")
except Exception:
    pass
