#!/usr/bin/env python3
"""kicemail staff_map-Generator: persoenliche lokale Empfangsadressen aus dem
Postfix-Verkehr (alle vorliegenden mail.log-Rotationen) ->
/var/lib/kicemail/staff_map.json.
Schreibt nur bei echter Aenderung; alte Version bleibt als .bak erhalten.
Allgemeine/System-Adressen werden abgezogen (NON_PERSONAL-Regex). Fail-open:
bei jedem Fehler bleibt die alte Map unangetastet."""
import json, re, glob, os, subprocess, sys, tempfile

STAFF_OUT = "/var/lib/kicemail/staff_map.json"
LOCAL = r"example\.com|example\.net"
# allgemeine + System-/Funktionsadressen -> NICHT ins Personalschema
NON_PERSONAL = re.compile(
    r"^(info|postmaster|abuse|noreply|no-reply|root|mailer-daemon|"
    r"buchhaltung|einkauf|vertrieb|bewerbung|fertigung|dmarc-reports|dmarc|"
    r"it-error|it-info|hostmaster|webmaster|archive|admin|office|kontakt|"
    r"verwaltung|servermanager|ki-spam|quarantaene|emailausgang|faxeingang|"
    r"faxausgang|autoresponse|mailerdaemon|spam|virus|sicherheitsupdates?)\b",
    re.I)
MIN_MSGS = 2   # gegen Tipfofen- und Einweg-Adressen

PAT = re.compile(r"to=<([a-z0-9._+-]+)@(" + LOCAL + r")>", re.I)


def read_lines(path):
    if path.endswith(".gz"):
        p = subprocess.Popen(["zcat", path], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        try:
            for line in p.stdout:
                yield line
        finally:
            p.stdout.close()
            p.wait()
    else:
        try:
            with open(path, encoding="utf-8", errors="replace") as h:
                for line in h:
                    yield line
        except OSError:
            return


def mine():
    files = sorted(["/var/log/mail.log"] + glob.glob("/var/log/mail.log.*"))
    counts = {}
    seen = set()
    for f in files:
        for line in read_lines(f):
            if "status=sent" not in line:
                continue
            if not PAT.search(line):
                continue
            line = line.strip()
            # Rotations-Dubletten (logrotate laesst mail.log.N und .N.gz
            # parallel zurueck) exakt einmal zaehlen
            if line in seen:
                continue
            seen.add(line)
            m = PAT.search(line)
            addr = m.group(1).lower() + "@" + m.group(2).lower()
            counts[addr] = counts.get(addr, 0) + 1
    return counts


def main():
    try:
        counts = mine()
    except Exception as e:
        print("mining failed (fail-open, alte Map bleibt):", e)
        return 0
    if not counts:
        print("keine traffic-Daten lesbar — nichts geschrieben")
        return 0
    staff = sorted(a for a, n in counts.items()
                   if n >= MIN_MSGS and not NON_PERSONAL.match(a.split("@")[0]))
    if not staff:
        print("Liste leer — nichts geschrieben")
        return 0
    try:
        old = json.load(open(STAFF_OUT, encoding="utf-8"))
    except (OSError, ValueError):
        old = None
    if old is not None and sorted(old) == staff:
        print("staff unchanged:", len(staff))
        return 0
    if old is not None:
        json.dump(old, open(STAFF_OUT + ".bak", "w"), indent=0)
    fd, tmp = tempfile.mkstemp(dir="/var/lib/kicemail")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(staff, f, indent=0)
    os.replace(tmp, STAFF_OUT)
    neu = set(staff) - set(old or [])
    weg = set(old or []) - set(staff)
    print("staff_map geschrieben:", len(staff), "| neu:", sorted(neu),
          "| raus:", sorted(weg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
