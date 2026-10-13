#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
amavis-correspondents.py — Auto-Whitelist der Geschäftskorrespondenten.

Wer eine Mail von uns bekommt, darf uns antworten:
Parst die Postfix-Logs (mail.log*, Fenster WINDOW_DAYS Tage) nach erfolgreich
nach EXTERN zugestellten Mails (status=sent, Relay öffentliche IP) und schreibt
die Domains der Empfänger nach /etc/amavis/whitelist-correspondents.txt.

Regeln:
  * kleinste Kosten: nur echte externe Zustellung (interne Relays 127./10./192.168. excluded)
  * Freemail-/Massenplattformen werden NICHT gewhitelistet (Blockliste)
  * eigene Domains werden übersprungen
  * Domains, die schon in /etc/amavis/whitelist-domains.txt (manuell) stehen,
    werden NICHT Duplikat in die Auto-Datei geschrieben
  * Datei wird nur geschrieben, wenn die Domains MENGE sich ändert
    (sonst kein unnötiger Amavis-Reload über die Path-Unit)
  * Fund = 0 Domains -> Abbruch ohne Änderung (Schutz bei Logrotation-Defekt)
  * Amavis-seitiges Extra-Dedupe: der Reader in /etc/amavis/conf.d/50-user
    normalisiert (kleinbuchstabig, führender Punkt egal) und verwirft Duplikate
"""
import argparse
import datetime as dt
import fcntl
import glob
import logging
import os
import re
import sys
import tempfile

WINDOW_DAYS = 90
LOG_GLOB = '/var/log/mail.log*'
STATIC_FILE = '/etc/amavis/whitelist-domains.txt'
OUT_FILE = '/etc/amavis/whitelist-correspondents.txt'
LOCK_FILE = '/run/lock/amavis-correspondents.lock'

OWN_DOMAINS = {
    'example.com', 'example.net', 'gateway', 'gateway.example.local',
    'mail.example.local', 'example.local',
}

# Freemail / Massen-Plattformen: nie automatisch whitelisten
BLOCK_EXACT = {
    'gmail.com', 'googlemail.com', 'googlemail.de', 'google.com',
    'web.de', 'gmx.de', 'gmx.net', 'gmx.at',
    't-online.de', 'arcor.de', '1und1.de', 'freenet.de',
    'posteo.de', 'posteo.net', 'mailbox.org',
    'outlook.com', 'outlook.de', 'outlook.at', 'outlook.fr',
    'live.com', 'live.de',
    'hotmail.com', 'hotmail.de', 'hotmail.at', 'hotmail.fr', 'hotmail.co.uk',
    'yahoo.com', 'yahoo.de', 'yahoo.fr', 'yahoo.it', 'yahoo.co.uk',
    'aol.com', 'aol.de',
    'icloud.com', 'me.com', 'mac.com',
    'protonmail.com', 'proton.me',
    'mail.ru', 'inbox.ru', 'list.ru', 'yandex.ru', 'yandex.com', 'yandex.de',
    'seznam.cz', 'post.cz', 'email.cz', 'centrum.cz',
    'infoemail.microsoft.com', 'unite.eu',
    'libero.it', 'orange.fr', 'wanadoo.fr', 'free.fr', 'laposte.net',
    'wp.pl', 'onet.pl', 'interia.pl',
    'amazonses.com', 'mailgun.org', 'sendgrid.net',
}
# alles unterhalb dieser Domains ist ebenso Massen-/Freemail-Terrain
BLOCK_SUFFIX = (
    'yahoo.com', 'yahoo.de', 'yahoo.fr', 'yahoo.it', 'yahoo.co.uk',
    'hotmail.com', 'hotmail.de', 'hotmail.fr', 'hotmail.it',
    'gmx.de', 'gmx.net', 'gmx.at', 'web.de',
    'yandex.ru', 'yandex.com', 'mail.ru',
    'outlook.com', 'outlook.de', 'live.com', 'live.de',
    'volkswagen-online.de',
)

DOMAIN_RE = re.compile(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$')
RELAY_RE = re.compile(r'relay=\S+?\[([0-9a-fA-F.:]+)\]:(\d+)')
TO_RE = re.compile(r'to=<[^<>@,]+@([^<>@,]+)>')
TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})T')

log = logging.getLogger('amavis-correspondents')


def open_log(path):
    if path.endswith('.gz'):
        import gzip
        return gzip.open(path, 'rt', errors='replace')
    return open(path, 'rt', errors='replace')


def is_private(ip):
    if ip.startswith(('127.', '::1', '10.', '192.168.')):
        return True
    if ip.startswith('::ffff:127.'):
        return True
    m = re.match(r'172\.(\d+)\.', ip)
    if m and 16 <= int(m.group(1)) <= 31:
        return True
    return False


def blocked(domain):
    if domain in BLOCK_EXACT:
        return True
    for s in BLOCK_SUFFIX:
        if domain == s or domain.endswith('.' + s):
            return True
    return False


def static_normalized():
    """Bereits manuell gepflegte Domains (normalisiert, ohne Punkt-Präfix)."""
    out = set()
    try:
        with open(STATIC_FILE, 'rt', errors='replace') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip().lower().lstrip('.').rstrip('.')
                if line:
                    out.add(line)
    except FileNotFoundError:
        pass
    return out


def current_generated_set():
    """Domains, die die generierte Datei aktuell enthält (normalisiert)."""
    out = set()
    try:
        with open(OUT_FILE, 'rt', errors='replace') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip().lower().lstrip('.').rstrip('.')
                if line:
                    out.add(line)
    except FileNotFoundError:
        pass
    return out


def collect_domains():
    cutoff = (dt.date.today() - dt.timedelta(days=WINDOW_DAYS - 1)).isoformat()
    domains = set()
    files = sorted(
        p for p in glob.glob(LOG_GLOB)
        if re.search(r'mail\.log(\.\d+)?(\.gz)?$', p)
    )
    seen_lines = 0
    for path in files:
        try:
            with open_log(path) as fh:
                for line in fh:
                    if 'status=sent' not in line:
                        continue
                    m = TS_RE.match(line)
                    if not m or m.group(1) < cutoff:
                        continue
                    rm = RELAY_RE.search(line)
                    if not rm or is_private(rm.group(1)):
                        continue
                    for d in TO_RE.findall(line):
                        d = d.strip().lower().rstrip('.')
                        if DOMAIN_RE.match(d) and d not in OWN_DOMAINS and not blocked(d):
                            domains.add(d)
                            seen_lines += 1
        except OSError as exc:
            log.warning('log file %s skipped: %s', path, exc)
    return domains, files, seen_lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()
    logging.basicConfig(
        format='amavis-correspondents[%(process)d]: %(message)s',
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    lock_fd = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.error('another run holds the lock, exiting')
        sys.exit(1)

    domains, files, hits = collect_domains()
    log.info('scanned %d file(s), %d recipient hits, %d unique domains',
             len(files), hits, len(domains))

    if not domains:
        log.error('ZERO correspondent domains found — refusing to overwrite %s', OUT_FILE)
        sys.exit(2)

    # Duplikate mit statischer Liste vermeiden (und untereinander ohnehin Set)
    static = static_normalized()
    dupes = sorted(d for d in domains if d in static)
    if dupes:
        log.info('skipping %d domain(s) already whitelisted statically: %s',
                 len(dupes), ' '.join(dupes))
        domains = {d for d in domains if d not in static}

    new_set = domains
    old_set = current_generated_set()
    if new_set == old_set:
        log.info('domain set unchanged (%d entries), not rewriting %s — no reload',
                 len(new_set), OUT_FILE)
        sys.exit(0)

    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    if added:
        log.info('added: %s', ' '.join(added))
    if removed:
        log.info('removed (no correspondence within %d days): %s', WINDOW_DAYS, ' '.join(removed))

    body = []
    body.append('# AUTO-GENERIERT — nicht von Hand editieren!')
    body.append('# Quelle: /usr/local/sbin/amavis-correspondents.py (Cron /etc/cron.d/amavis-correspondents)')
    body.append('# Inhalt: Domains, an die wir in den letzten %d Tagen erfolgreich nach extern zugestellt haben.' % WINDOW_DAYS)
    body.append('# Regel:  wer eine Mail von uns bekommt, darf uns antworten (Amavis-Spamscore-Bypass, Virenscan bleibt).')
    body.append('# Manuelle Einträge gehören in %s — daraus resultierende Duplikate werden übersprungen.' % STATIC_FILE)
    body.append('# Generiert: %s' % dt.datetime.now().isoformat(timespec='seconds'))
    body.append('')
    for d in sorted(new_set):
        body.append('.%s' % d)
    body.append('')
    content = '\n'.join(body)

    if args.dry_run:
        log.info('dry-run, would write %d entries to %s:', len(new_set), OUT_FILE)
        print(content)
        sys.exit(0)

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(OUT_FILE), prefix='.wl-')
    try:
        with os.fdopen(fd, 'w') as fh:
            fh.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, OUT_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    log.info('wrote %d entries to %s (Reload erfolgt automatisch ueber amavis-whitelist.path)', len(new_set), OUT_FILE)
    # Kein explizites systemctl-reload hier! Das wuerde mit dem Reload der
    # Path-Unit (trigert auf os.replace zuverlässig) rasen; zwei
    # SIGHUPs kurz nacheinander haben auf diesem Host den Master gekillt.


if __name__ == '__main__':
    main()
