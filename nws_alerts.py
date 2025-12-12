#!/usr/bin/env python3
"""
Fetch recent NWS alerts for multiple UGC zones and keep exactly ONE
Discord webhook message per logical alert chain (Alert→Updates→Cancel).

State is stored in one JSON file per zone (no SQLite needed).
Runs once, does its work, then exits — perfect for a 1-minute cron job.
"""

import os
import re
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
from typing import Dict, Any, List

import requests
from dateutil.parser import isoparse
from urllib.parse import urlencode, quote

# ─────────────────────────  your table of codes  ─────────────────────────
from lib.utility_module import event_codes     # unchanged

# ─────────────────────────  CONSTANTS  ─────────────────────────
APP_NAME   = "icad_nws_alerts"
__version__ = "1.0.0"

UTC = timezone.utc

VTEC_RE = re.compile(
    r"/[A-Z]\.(NEW|CON|EXT|EXA|EXB|UPG|CAN|COR|EXP)\.([A-Z]{4})\.([A-Z]{2})\.([A-Z])\.(\d{4})\."
)

SEVERITY_COLOR = {
    "Extreme":  0x8B0000,
    "Severe":   0xFF0000,
    "Moderate": 0xFD8D14,
    "Minor":    0xFFFF00,
    "Unknown":  0x808080,
}

def get_log_level(name: str | None) -> int:
    """Map string/int env or config values to logging levels."""
    if name is None:
        return logging.INFO
    if isinstance(name, int):
        return name
    name = name.upper()
    return {
        "CRITICAL": logging.CRITICAL,
        "ERROR":    logging.ERROR,
        "WARNING":  logging.WARNING,
        "INFO":     logging.INFO,
        "DEBUG":    logging.DEBUG,
    }.get(name, logging.INFO)


def resolve_paths() -> tuple[Path, Path, Path]:
    """
    Returns (cfg_path, log_dir, state_dir), all rooted at the script's directory
    unless overridden via env vars.

    Layout (default):
      <repo-root>/etc/config.json
      <repo-root>/var/log/
      <repo-root>/var/state/
    """
    base = Path(__file__).resolve().parent

    cfg_path  = Path(os.environ.get("NOAA_ALERTS_CONFIG",  base / "etc" / "config.json"))

    # Single var/ root, then split into log/ and state/
    var_dir   = Path(os.environ.get("NOAA_ALERTS_VARDIR",  base / "var"))
    log_dir   = Path(os.environ.get("NOAA_ALERTS_LOGDIR",  var_dir / "log"))
    state_dir = Path(os.environ.get("NOAA_ALERTS_STATEDIR", var_dir / "state"))

    return cfg_path, log_dir, state_dir

# ─────────────────────────  LOGGING  ─────────────────────────
def setup_logging(
        log_dir: Path,
        filename: str = f"{APP_NAME}.log",
        level: int = logging.INFO,
        backup_days: int = 14,
) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / filename

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    fh = TimedRotatingFileHandler(
        log_path,
        when="midnight",
        backupCount=backup_days,
        utc=True,
    )
    fh.setFormatter(fmt)
    fh.setLevel(level)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    ch.setLevel(level)

    root.handlers[:] = [fh, ch]
    return logging.getLogger(APP_NAME)


# ─────────────────────────  CONFIG  ─────────────────────────

def load_config(config_path: Path, state_dir: Path) -> Dict[str, Any]:
    if not config_path.exists():
        raise SystemExit(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    # required
    zones = cfg.get("zones")
    if not zones or not isinstance(zones, list):
        raise SystemExit("config.json must include a non-empty 'zones' list")

    # defaults
    cfg.setdefault("user_agent", f"{APP_NAME}/{__version__} (noaa-alerts@icaddispatch.com)")
    cfg.setdefault("state_dir", str(state_dir))
    cfg.setdefault("log_level", "INFO")

    # NEW: Mapbox token (optional). If unset, maps are skipped silently.
    cfg.setdefault("mapbox_token", None)

    # ensure state dir exists
    Path(cfg["state_dir"]).mkdir(parents=True, exist_ok=True)

    return cfg

# ─────────────────────────  STATE (JSON)  ─────────────────────────

def state_path(cfg: Dict[str, Any], zone_id: str) -> str:
    return os.path.join(cfg["state_dir"], f"{zone_id}.json")

def load_state(cfg: Dict[str, Any], zone_id: str) -> Dict[str, Any]:
    """
    Returns:
      {
        "alerts": {
            "<canonical_id>": {
               "cap_id": "...",
               "discord_id": "...",
               "status": "posted|updated|cleared",
               "expires_at": "ISO-8601"
            },
            ...
        }
      }
    """
    path = state_path(cfg, zone_id)
    if not os.path.exists(path):
        return {"alerts": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.error("Failed to read state file %s: %s (starting empty)", path, e)
        return {"alerts": {}}

def save_state(cfg: Dict[str, Any], zone_id: str, state: Dict[str, Any]) -> None:
    """
    Atomic write to avoid corruption.
    """
    path = state_path(cfg, zone_id)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp_path, path)

def prune_state(state: Dict[str, Any], now: datetime) -> None:
    """
    Remove any chain whose expires_at is >7 days in the past.
    """
    cutoff = (now - timedelta(days=7)).isoformat()
    alerts = state.get("alerts", {})
    doomed = [cid for cid, r in alerts.items() if r.get("expires_at", "") < cutoff]
    for cid in doomed:
        del alerts[cid]

# ───────────────────────  NOAA API helpers  ───────────────────────

def hazard_color(props: dict) -> int:
    return SEVERITY_COLOR.get(props.get("severity", "Unknown"), 0x808080)

def fetch_recent_alerts(zone_id: str, ua: str) -> List[dict]:
    """
    Pull EVERYTHING the NWS still lists as *status=actual* for the zone.
    No time window – that way we never miss an older alert if the job was down.
    """
    headers = {
        "User-Agent": ua,
        "Accept": "application/geo+json",
    }
    params = {
        "zone": zone_id,
        "status": "actual",
        "limit": 500,
    }
    url = f"https://api.weather.gov/alerts?{urlencode(params)}"
    log.debug("GET %s", url)
    r = requests.get(url, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()["features"]

def vtec_key(props: dict) -> str | None:
    """
    Return 'OFFICE-PHENSIG-ETN' (e.g. 'KBGM-HT.Y-0006') if a VTEC line exists,
    otherwise None.
    """
    for line in props.get("parameters", {}).get("VTEC", []):
        m = VTEC_RE.match(line)
        if m:
            office, phensig, sub, etn = m.group(2), m.group(3), m.group(4), m.group(5)
            return f"{office}-{phensig}.{sub}-{etn}"
    return None

def canonical_id(alert_id: str) -> str:
    # urn:oid:... .003.1  -> strip last two numeric parts
    parts = alert_id.split(".")
    return ".".join(parts[:-2])

def chain_key(props: dict) -> str:
    return vtec_key(props) or canonical_id(props["id"])

def latest_by_chain(features: List[dict]) -> Dict[str, dict]:
    latest = {}
    for f in sorted(features, key=lambda f: f["properties"]["sent"], reverse=True):
        k = chain_key(f["properties"])
        if k not in latest:
            latest[k] = f
    return latest

# ───────────────────────  Discord helpers  ───────────────────────

def discord_post_embed(embed: dict, webhook_url: str) -> str:
    payload = {
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }
    url = webhook_url + ("&wait=true" if "?" in webhook_url else "?wait=true")
    r = requests.post(url, json=payload, timeout=15)
    r.raise_for_status()
    return r.json()["id"]

def discord_edit_embed(msg_id: str, embed: dict, webhook_url: str):
    url_base = webhook_url.split("?", 1)[0]
    url = f"{url_base}/messages/{msg_id}"
    payload = {
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }
    r = requests.patch(url, json=payload, timeout=15)
    r.raise_for_status()

def event_icon(props: dict) -> str:
    """
    Return the emoji/icon for this alert, falling back to ℹ️ when unknown.
    Priority:
        1) Any code in `eventCode["NationalWeatherService"]`
        2) Any code in `eventCode["SAME"]`
        3) The full event text (rare fallback)
    """
    e_codes = props.get("eventCode", {})

    for c in e_codes.get("NationalWeatherService", []):
        if c in event_codes:
            return event_codes[c]["icon"]

    for c in e_codes.get("SAME", []):
        if c != "NWS" and c in event_codes:
            return event_codes[c]["icon"]

    return event_codes.get(props.get("event", ""), {}).get("icon", "ℹ️")

# ───────────────────────  Mapbox static map helper (NEW)  ───────────────────────

def build_mapbox_static_url(cfg: Dict[str, Any], feat: dict) -> str | None:
    """
    Build a Mapbox Static Images URL that overlays the alert polygon (GeoJSON).
    If no token is configured or no geometry is present, returns None.
    """
    token = cfg.get("mapbox_token")
    if not token:
        return None

    geometry = feat.get("geometry")
    if not geometry:
        return None

    geojson = {
        "type": "Feature",
        "geometry": geometry,
        "properties": {
            "stroke": "#ff0000",
            "stroke-width": 2,
            "fill": "#ff0000",
            "fill-opacity": 0.25,
        },
    }

    geojson_str = json.dumps(geojson, separators=(",", ":"))
    geojson_enc = quote(geojson_str, safe="")

    # auto center, auto zoom
    return (
        "https://api.mapbox.com/styles/v1/mapbox/light-v11/static/"
        f"geojson({geojson_enc})/"
        "auto/800x500"
        f"?access_token={token}"
    )

def build_embed(props: dict, cleared: bool = False) -> dict:
    ev_icon = event_icon(props)

    # Title (short!) – Discord hard limits to 256 chars.
    headline = props.get("headline") or props["event"]
    max_len  = 254 - len(ev_icon)
    if len(headline) > max_len:
        headline = headline[:max_len - 1] + "…"

    title_txt = f"{ev_icon} {headline}"
    if cleared:
        title_txt = f"~~{title_txt}~~ – CANCELLED"

    # Times
    starts = props.get("effective") or props["sent"]
    ends   = props.get("ends") or props.get("expires") or "—"

    # Risk trio
    sev = props.get("severity", "Unknown").title()
    urg = props.get("urgency", "Unknown").title()
    cer = props.get("certainty", "Unknown").title()
    risk = f"**{sev} • {urg} • {cer}**"

    # Area preview
    areas = props.get("areaDesc", "").split("; ")
    area_field = ", ".join(areas[:3]) + (f" … (+{len(areas)-3} more)" if len(areas) > 3 else "")

    # Description
    # CHANGED (per your request): keep FULL text, no paragraph split, no truncation
    descr = (props.get("description", "") or "").strip()

    return {
        "title": title_txt,
        "url": props.get("@id") or props.get("id"),
        "description": descr,
        "color": hazard_color(props),
        "timestamp": props["sent"],
        "fields": [
            {"name": "Starts",   "value": starts,     "inline": True},
            {"name": "Ends",     "value": ends,       "inline": True},
            {"name": "Severity", "value": risk,       "inline": False},
            {"name": "Affected", "value": area_field, "inline": False},
        ],
        "footer": {
            "text": f"{props.get('senderName','NWS')} – "
                    f"{datetime.fromisoformat(props['sent']).strftime('%b %d %I:%M %p')}"
        }
    }

# ───────────────────────  Alert life-cycle helpers  ───────────────────────

def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return isoparse(ts).astimezone(UTC)

def event_end_iso(props: dict) -> str | None:
    ends = props.get("ends")
    if ends:
        return ends
    end_param = (props.get("parameters", {}).get("eventEndingTime") or [None])[0]
    if end_param:
        return end_param
    return None

def derive_expires(props: dict) -> str:
    t_end = (parse_iso(event_end_iso(props)) or parse_iso(props.get("expires")))
    if not t_end:
        t_end = datetime.now(UTC) + timedelta(days=14)
    return t_end.isoformat()

def _first(*vals):
    return next((v for v in vals if v), None)

def is_still_effective(props: dict, now: datetime) -> bool:
    if props.get("messageType", "").lower() == "cancel":
        return False
    if "replacedBy" in props:
        return False

    t_end = _first(
        parse_iso(props.get("expires")),
        parse_iso(props.get("ends")),
        parse_iso((props.get("parameters", {}).get("eventEndingTime") or [None])[0]),
    )
    return not (t_end and now >= t_end)

# ───────────────────────  Runner (per zone)  ───────────────────────

def run_for_zone(cfg: Dict[str, Any], zone: Dict[str, Any]) -> None:
    zone_id   = zone["zone_id"]
    webhooks  = zone.get("webhooks", [])
    if not webhooks:
        log.warning("No webhook configured for zone %s – skipping", zone_id)
        return

    state = load_state(cfg, zone_id)
    now   = datetime.now(UTC)

    try:
        feats = fetch_recent_alerts(zone_id, cfg.get("user_agent", "noaa_alerts_bot"))
    except Exception as e:
        log.exception("NWS fetch failed for %s: %s", zone_id, e)
        return

    latest = latest_by_chain(feats)
    cur    = state.get("alerts", {})

    # Process chains oldest → newest so Discord posts are in chronological order
    for cid, feat in sorted(latest.items(), key=lambda kv: kv[1]["properties"]["sent"]):
        props   = feat["properties"]
        cap_id  = props["id"]
        row     = cur.get(cid)
        active  = is_still_effective(props, now)
        cleared = not active

        try:
            embed = build_embed(props, cleared)

            # NEW: attach map image (if configured + geometry exists)
            map_url = build_mapbox_static_url(cfg, feat)
            if map_url:
                embed["image"] = {"url": map_url}

            if row is None:
                # Never seen this chain before
                if cleared:
                    log.debug("[%s] Skipped expired %s (never seen)", zone_id, cid)
                    continue

                # Still active → post now (use 1st webhook only, or all – your choice)
                msg_id = discord_post_embed(embed, webhooks[0])

                cur[cid] = {
                    "cap_id":     cap_id,
                    "discord_id": msg_id,
                    "status":     "posted",
                    "expires_at": derive_expires(props),
                }
                log.info("[%s] Posted %s (new)", zone_id, cid)

            else:
                row_status      = row["status"]
                already_cleared = (row_status == "cleared")
                should_edit     = (cap_id != row["cap_id"]) or (cleared and not already_cleared)

                if not should_edit:
                    continue

                # Patch the message
                try:
                    discord_edit_embed(row["discord_id"], embed, webhooks[0])
                except requests.HTTPError as e:
                    # Discord returned 404? Re-post and replace the id.
                    if e.response is not None and e.response.status_code == 404:
                        log.warning("[%s] Discord 404 for %s – re-posting", zone_id, cid)
                        new_id = discord_post_embed(embed, webhooks[0])
                        row["discord_id"] = new_id
                    else:
                        raise

                row["cap_id"]     = cap_id
                row["status"]     = "cleared" if cleared else "updated"
                row["expires_at"] = derive_expires(props)
                log.info("[%s] Edited %s (%s)", zone_id, cid, row["status"])

        except Exception as e:
            log.exception("[%s] Discord failure for %s: %s", zone_id, cid, e)

    # Prune very old stuff and persist
    prune_state(state, now)
    state["alerts"] = cur
    save_state(cfg, zone_id, state)

# ─────────────────────────  main  ─────────────────────────

def main():
    # Resolve paths (env overrides supported)
    cfg_path, log_dir, state_default = resolve_paths()

    # If the config is missing, fail fast *before* we even try to log to file.
    if not cfg_path.exists():
        # minimal console logger so the user sees _something_
        logging.basicConfig(level=logging.ERROR, format="%(asctime)s  %(levelname)s  %(message)s")
        logging.error("Config file %s not found. Aborting.", cfg_path)
        raise SystemExit(2)

    # Load config now (so we can grab log_level), then initialize full logging
    tmp_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    level   = get_log_level(tmp_cfg.get("log_level") or os.environ.get("NOAA_ALERTS_LOGLEVEL"))

    global log
    log = setup_logging(log_dir, f"{APP_NAME}.log", level=level)

    # Re-load using our loader (so it also validates & creates state_dir)
    cfg = load_config(cfg_path, state_default)

    log.info("Starting %s %s with config=%s", APP_NAME, __version__, cfg_path)

    # Run each zone
    for zone in cfg["zones"]:
        try:
            run_for_zone(cfg, zone)
        except Exception:
            log.exception("Unhandled error while processing zone %s", zone.get("zone_id"))

    log.info("Run completed.")

if __name__ == "__main__":
    main()
