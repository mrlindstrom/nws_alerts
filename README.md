# icad_nws_alerts

Fetch recent **NWS weather alerts** for one or more **UGC zones** and keep **exactly one Discord message per logical alert chain** (Alert → Updates → Cancel).

The script:

- Polls `api.weather.gov/alerts` (no time window, so downtime won’t miss alerts still marked `status=actual`).
- **Posts** brand‑new, still‑active alerts to Discord.
- **Edits** the same Discord message when that alert is **updated / canceled / expired**.
- **Ignores** alerts that are already over if the script never saw them (no retro spam).
- Stores state in **one JSON file per zone** (no DB).
- Uses **daily log rotation**.

Designed to run every minute on **Linux** via **cron** (or a systemd timer) inside a **Python virtual environment**.

---

## Features

- Multiple zones, each with its own Discord webhook list.
- Robust de‑dup with **VTEC chain keys** (falls back to canonical CAP id).
- Automatic recovery if a Discord edit returns **404** (re‑post & update state).
- Safe, atomic JSON writes.
- Daily rotated logs with retention.
- Optional: mapbox integration that will draw the alert polygons (if present)

---

## Requirements

- **Linux**
- **Python 3.10+**
- Discord **webhook URL(s)**

### Python packages

```text
requests
python-dateutil
```

(or keep them in a `requirements.txt`)

---

## Directory layout (default)

```text
repo/
├── icad_nws_alerts.py          # the script
├── lib/
│   └── utility_module.py       # contains event_codes
├── etc/
│   └── config.json             # copy from config_sample.json
├── var/
│   ├── log/
│   │   └── icad_nws_alerts.log # rotated daily
│   └── state/
│       └── <ZONE>.json         # one state file per zone
└── venv/                       # (optional) python virtualenv
```

You can override all paths with environment variables (see **Environment variables**).

---

## Getting NOAA **UGC zone IDs** (county / forecast zones)

You need **UGC** zone IDs (e.g., `SCC063`) for the `zone` query parameter.

### Quick via API

List all **county** zones for a state (example: South Carolina):

```bash
curl -s "https://api.weather.gov/zones?type=county&area=SC" \
| jq -r '.features[] | "\(.properties.id)\t\(.properties.name)"'
```

Inspect one zone:

```bash
curl -s "https://api.weather.gov/zones/county/SCC063" | jq .
```

You can also find tables on NWS / WFO websites that map counties to UGC IDs.

> **Note**: UGC zones are different from SAME (EAS) FIPS codes. This script uses **UGC**.

---

## Configuration (`etc/config.json`)

Example:

```json
{
  "user_agent": "icad_nws_alerts (ops@example.com)",
  "log_level": "INFO",
  "zones": [
    {
      "zone_id": "SCC063",
      "label": "Lexington County, SC",
      "webhooks": [
        "https://discord.com/api/webhooks/xxx/yyy"
      ]
    },
    {
      "zone_id": "NYC015",
      "label": "Chemung County, NY",
      "webhooks": [
        "https://discord.com/api/webhooks/aaa/bbb"
      ]
    }
  ]
}
```

**Notes**

- `zones[].webhooks`: The script currently uses the **first** webhook. (You can fan out yourself if desired.)

---

## Environment variables (optional)

- `NOAA_ALERTS_CONFIG`   – full path to `config.json`. Default: `<repo>/etc/config.json`
- `NOAA_ALERTS_VARDIR`   – base dir for `log/` and `state/`. Default: `<repo>/var`
- `NOAA_ALERTS_LOGDIR`   – logs dir. Default: `<var>/log`
- `NOAA_ALERTS_STATEDIR` – state dir. Default: `<var>/state`
- `NOAA_ALERTS_LOGLEVEL` – overrides the `log_level` in config

---

## Install & Run (Linux + venv)

### 1) Clone & create venv

```bash
git clone https://github.com/TheGreatCodeholio/nws_alerts.git
cd icad_nws_alerts

python3 -m venv venv
source venv/bin/activate

pip install -U pip
pip install requests python-dateutil
```

### 2) Configure

```bash
mkdir -p etc var/log var/state
cp etc/config_sample.json etc/config.json
vim etc/config.json
```

### 3) Test run

```bash
source venv/bin/activate
python icad_nws_alerts.py
```

### 4) Cron (every minute)

```bash
crontab -e
```

Add:

```text
* * * * * cd /opt/icad_nws_alerts && /opt/icad_nws_alerts/venv/bin/python icad_nws_alerts.py >> /opt/icad_nws_alerts/var/log/cron.out 2>&1
```

(Adjust paths to your install.)

**Tips**

- Always use **full paths** in cron.
- If you rely on env vars, either set them inline or wrap the call in a shell script that exports them first.

---

## (Optional) systemd timer instead of cron

Create `/etc/systemd/system/icad_nws_alerts.service`:

```ini
[Unit]
Description=icad_nws_alerts runner

[Service]
Type=oneshot
WorkingDirectory=/opt/icad_nws_alerts
Environment=NOAA_ALERTS_CONFIG=/opt/icad_nws_alerts/etc/config.json
ExecStart=/opt/icad_nws_alerts/venv/bin/python /opt/icad_nws_alerts/icad_nws_alerts.py
```

Create `/etc/systemd/system/icad_nws_alerts.timer`:

```ini
[Unit]
Description=Run icad_nws_alerts every minute

[Timer]
OnUnitActiveSec=60s
AccuracySec=5s
Unit=icad_nws_alerts.service

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now icad_nws_alerts.timer
```

---

## Posting/editing rules (summary)

- **New alert + active** → **post**.
- **New alert + already canceled/expired** → **ignore**.
- **Seen alert updated** → **edit** that Discord message.
- **Seen alert canceled/expired** → **edit** to show cancelled.
- **Edit returns 404** → **re‑post** and update stored message id.
- **Prune** state entries 7 days after `expires_at`.

---

## Logging

- Logs live in `<var>/log/icad_nws_alerts.log`.
- Rotated **nightly** (UTC), keep **14 days** by default.
- Change via config/env vars.

---

## State files

- One JSON per zone: `<var>/state/<ZONE>.json`
- Holds:
    - last CAP id you posted/edited for the chain
    - Discord message id
    - status (`posted|updated|cleared`)
    - `expires_at`
- Written atomically (`.tmp` + replace) to avoid corruption.

---

## Troubleshooting

**Discord 404 on edit**
- Discord may purge webhook messages or someone deleted it.
- The script detects 404 and re‑posts, updating state.

**Works manually but not from cron**
- Cron has a **minimal environment** and a different working dir.
- Use **absolute paths** and ensure your venv path is correct.

**Missing alerts**
- Verify the **correct UGC zone** is used.
- Script ignores **already‑over** alerts it has never seen.

**Timezone confusion**
- Script normalizes timestamps to **UTC** using `python-dateutil`.

---

## Contributing

PRs welcome! Please keep:
- Backward compatibility of state JSON if possible
- Same logging & error‑handling style
- Minimal external dependencies

---

## License

MIT License

---

## Credits

- NWS `api.weather.gov`
- Discord Webhooks
