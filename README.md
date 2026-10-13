# kicemail — KI-gestützte E-Mail-Klassifizierung für Postfix/Amavis

Kleine, dependency-free Mail-Pipeline (nur Python-3-stdlib), die eingehende
E-Mails mit einem lokalen LLM (OpenAI-kompatibles API) klassifiziert und mit
`X-KI-*`-Headern versieht. Grundsatz: **Fail-open** — Mail-Zustellung ist bei
jeden KI-Fehler/Timeout garantiert, Header fehlen dann einfach.

## Komponenten (`sbin/`)

| Datei | Zweck |
|---|---|
| `kicemail-milter.py` | SMTP-Milter: klassifiziert im Zustellpfad, setzt `X-KI-Class`, `X-KI-Conf`, `X-KI-Auto`, `X-KI-Fehler`, führt JSON-Log + Archiv |
| `kicemail-daemon.py` | Phase-0-Spool-Watcher (Side-Channel-Klassifizierung, Legacy/optional) |
| `kicemail-staff-map.py` | mineriert persönliche Empfangsadressen aus `mail.log` → `staff_map.json` (für Fehladressierungs-Erkennung) |
| `kicemail-dailystats.py` | Tagesstatistik aus `kiclass.log` |
| `kicemail-probe.sh` | kompakter Zustands-Check für Watchdogs (Dienste, Queue, API, Fehlerquote) |
| `amavis-correspondents.py` | Korrespondenten-/Domain-Whitelists aus Amavis-Logs nachführen |

## Klassifizierung

- Klassen konfigurierbar in `/etc/kicemail/kicemail.conf`
  (Geschäftsverkehr, Angebote, Spam-Klassen, Newsletter, Rechnungen,
  Transaktionsmails, `systemprotokoll`, `privat`, `unklar`, …)
- `X-KI-Auto: yes|no` — ja nur bei Confidence ≥ Schwelle (`auto_min_conf`),
  ohne Spoof-Verdacht, außerhalb der `auto_exclude`-Klassen; bei
  `systemprotokoll` zusätzlich Ampel: `X-KI-Fehler: yes` erzwingt `no`
- Anhänge: PDF (Poppler-Container, optional) und Bild-OCR/Vision (optional)
- Chunked Reading: der Milter kann dem Modell fortlaufende Textabschnitte
  nachliefern, sodass Fehlermeldungen am Ende langer Protokolle nicht durch
  eine statische Kürzung verloren gehen (Runden-/Zeitbudget in der Config)
- Whitelist ist nur ein **Flag** im Prompt, kein Überspringen der KI

## Aufbau / Integration

1. `sbin/*` nach `/usr/local/sbin`, ausführbar machen
2. `etc/kicemail.conf.example` → `/etc/kicemail/kicemail.conf`,
   insbesondere `api_url` auf euer OpenAI-kompatibles Endpoint setzen
3. Postfix/Amavis: den Milter in den Injektions-Pfad der eingehenden Mails
   einhängen (bei uns: Amavis → Postfix-Pickup auf Port 10025 mit
   `smtpd_milters` auf den kicemail-Sockel/Port 11335), `reload`
4. `systemd/*.service` → `/etc/systemd/system/`, `daemon-reload`,
   `systemctl enable --now kicemail-milter`
5. optional Verzeichnis-/Logpfade anlegen:
   `/var/log/kicemail`, `/var/lib/kicemail/{spool,archive}`
6. `cron.d/*` → `/etc/cron.d/` (staff-Map + Amavis-Korrespondenten)

Der Milter setzt **keine** own Aktionen (kein Reject/Redirect) — er markiert
nur. Ablage/Weiterverarbeitung passiert stromabwärts, z. B. per
Header-basierter Regel im Mailserver (Bedingung typischerweise:
`X-KI-Class = systemprotokoll` UND `X-KI-Auto = yes` → Ordner).

## Protokolle & Aufbewahrung

- `/var/log/kicemail/kiclass.log` — JSON-zeilen, eine pro Mail (Klasse,
  Confidence, Latenz, Flags)
- `/var/lib/kicemail/archive` — Original-Mails als `.eml`, Rotation nach
  `archive_keep_days` (Standard 90; nur externe Mails)

## Sicherheitsdesign

- Fail-open bei KI-Fehler/Timeout: keine Header, normale Zustellung
- Spoof-Erkennung vorgetäuschter eigener Domains (Header-Signal)
- Kein Trainings-/Archivpfad für interne Korrespondenz (Config-Schalter
  `classify_internal` markiert, archiviert aber nicht)
- Milter-Prozess ohne Root, `NoNewPrivileges`, `ProtectSystem=full`

## Hinweis zur Konfigurationsdatei

Die mitgelieferte `etc/kicemail.conf.example` ist die produktive Konfiguration
einer Postfix/Amavis/MDaemon-Umgebung mit anonymisierten/adaptierten Werten —
Domains, Klassen und Schwellen müssen für die eigene Umgebung angepasst werden.
Der Code selbst enthält keine Zugangsdaten; das KI-Endpoint braucht kein Auth
(im LAN vorausgesetzt) und ist auf `127.0.0.1:4000` dokumentiert.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
