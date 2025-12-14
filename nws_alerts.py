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
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlencode
from io import BytesIO

import requests
from dateutil.parser import isoparse

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

# ─────────────────────────  MAP ADDITIONS BEGIN  ─────────────────────────
MAP_ATTACHMENT_FILENAME = "alert_map.png"

MAPBOX_STYLE_DEFAULT = "mapbox/light-v11"
MAP_WIDTH  = 900
MAP_HEIGHT = 550

MAP_FILL_RGBA   = (255, 0, 0, 70)    # semi-transparent fill
MAP_STROKE_RGBA = (255, 0, 0, 230)   # outline
MAP_STROKE_W    = 3

MAP_PAD_FRAC    = 0.07
MAP_PAD_MIN_DEG = 0.05
MAP_DRAW_MARGIN = 10
# ─────────────────────────  MAP ADDITIONS END  ─────────────────────────


# ─────────────────────────  LOGGING  ─────────────────────────

def get_log_level(name: str | None) -> int:
    if not name:
        return logging.INFO
    if isinstance(name, int):
        return name
    return getattr(logging, name.upper(), logging.INFO)


def resolve_paths(cli_config: Optional[str] = None) -> tuple[Path, Path, Path]:
    base = Path(__file__).resolve().parent

    cfg_path = Path(cli_config).resolve() if cli_config else Path(
        os.environ.get("NOAA_ALERTS_CONFIG", base / "etc" / "config.json")
    )

    var_dir   = Path(os.environ.get("NOAA_ALERTS_VARDIR", base / "var"))
    log_dir   = Path(os.environ.get("NOAA_ALERTS_LOGDIR", var_dir / "log"))
    state_dir = Path(os.environ.get("NOAA_ALERTS_STATEDIR", var_dir / "state"))

    return cfg_path, log_dir, state_dir


def setup_logging(log_dir: Path, level: int) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)s  %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    fh = TimedRotatingFileHandler(
        log_dir / f"{APP_NAME}.log",
        when="midnight",
        backupCount=14,
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

def load_config(path: Path, state_dir: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    if not cfg.get("zones"):
        raise SystemExit("config.json must include a non-empty 'zones' list")

    cfg.setdefault("user_agent", f"{APP_NAME}/{__version__}")
    cfg.setdefault("state_dir", str(state_dir))
    cfg.setdefault("log_level", "INFO")

    cfg.setdefault("mapbox_token", os.environ.get("MAPBOX_TOKEN"))
    cfg.setdefault("mapbox_style", MAPBOX_STYLE_DEFAULT)

    Path(cfg["state_dir"]).mkdir(parents=True, exist_ok=True)
    return cfg


# ─────────────────────────  STATE  ─────────────────────────

def state_path(cfg: Dict[str, Any], zone_id: str) -> str:
    return os.path.join(cfg["state_dir"], f"{zone_id}.json")


def load_state(cfg: Dict[str, Any], zone_id: str) -> Dict[str, Any]:
    try:
        with open(state_path(cfg, zone_id), "r") as f:
            return json.load(f)
    except Exception:
        return {"alerts": {}}


def save_state(cfg: Dict[str, Any], zone_id: str, state: Dict[str, Any]):
    tmp = state_path(cfg, zone_id) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, state_path(cfg, zone_id))


def prune_state(state: Dict[str, Any], now: datetime):
    cutoff = (now - timedelta(days=7)).isoformat()
    for k in list(state["alerts"]):
        if state["alerts"][k]["expires_at"] < cutoff:
            del state["alerts"][k]


# ───────────────────────  NOAA API helpers  ───────────────────────

def fetch_recent_alerts(zone_id: str, ua: str) -> List[dict]:
    headers = {"User-Agent": ua, "Accept": "application/geo+json"}
    params = {"zone": zone_id, "status": "actual", "limit": 500}
    url = f"https://api.weather.gov/alerts?{urlencode(params)}"
    log.debug("GET %s", url)
    r = requests.get(url, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()["features"]


def canonical_id(alert_id: str) -> str:
    return ".".join(alert_id.split(".")[:-2])


def chain_key(props: dict) -> str:
    for v in props.get("parameters", {}).get("VTEC", []):
        m = VTEC_RE.match(v)
        if m:
            return f"{m.group(2)}-{m.group(3)}.{m.group(4)}-{m.group(5)}"
    return canonical_id(props["id"])


def latest_by_chain(features: List[dict]) -> Dict[str, dict]:
    out = {}
    for f in sorted(features, key=lambda f: f["properties"]["sent"], reverse=True):
        k = chain_key(f["properties"])
        if k not in out:
            out[k] = f
    return out


# ───────────────────────  Discord helpers  ───────────────────────

def discord_post_embed(embed: dict, webhook: str, file: Optional[Tuple[str, bytes]] = None) -> str:
    url = webhook + ("&wait=true" if "?" in webhook else "?wait=true")

    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}

    if not file:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()["id"]

    fname, data = file
    payload["attachments"] = [{"id": 0, "filename": fname}]
    files = {"files[0]": (fname, data, "image/png")}
    r = requests.post(
        url,
        data={"payload_json": json.dumps(payload)},
        files=files,
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["id"]


def discord_edit_embed(msg_id: str, embed: dict, webhook: str):
    url = f"{webhook.split('?',1)[0]}/messages/{msg_id}"
    r = requests.patch(url, json={"embeds": [embed]}, timeout=30)
    r.raise_for_status()


# ───────────────────────  EMBED  ───────────────────────

def event_icon(props: dict) -> str:
    for c in props.get("eventCode", {}).get("NationalWeatherService", []):
        if c in event_codes:
            return event_codes[c]["icon"]
    return "ℹ️"


def build_embed(props: dict, cleared: bool) -> dict:
    title = f"{event_icon(props)} {props.get('headline') or props['event']}"
    if cleared:
        title = f"~~{title}~~ – CANCELLED"

    return {
        "title": title[:256],
        "description": (props.get("description") or "")[:4096],
        "color": SEVERITY_COLOR.get(props.get("severity"), 0x808080),
        "timestamp": props["sent"],
        "fields": [
            {"name": "Starts", "value": props.get("effective") or props["sent"], "inline": True},
            {"name": "Ends", "value": props.get("ends") or props.get("expires") or "—", "inline": True},
            {"name": "Affected", "value": props.get("areaDesc",""), "inline": False},
        ],
    }


# ───────────────────────  MAP LOGIC  ───────────────────────

def render_map_png(cfg: Dict[str, Any], props: dict, ua: str) -> Optional[bytes]:
    if not cfg.get("mapbox_token"):
        log.debug("Map: no mapbox token")
        return None

    try:
        from shapely.geometry import shape
        from shapely.ops import unary_union
        from pyproj import Transformer
        from PIL import Image, ImageDraw
    except Exception:
        log.debug("Map: missing dependencies")
        return None

    geoms = []

    # 1) geocode.UGC → county zones
    for ugc in props.get("geocode", {}).get("UGC", []):
        if isinstance(ugc, str) and len(ugc) == 6 and ugc[2] == "C":
            url = f"https://api.weather.gov/zones/county/{ugc}"
            try:
                r = requests.get(url, headers={"User-Agent": ua}, timeout=20)
                r.raise_for_status()
                geoms.append(shape(r.json()["geometry"]))
                log.debug("Map: got county %s", ugc)
            except Exception:
                pass

    # 2) affectedZones
    for url in props.get("affectedZones", []):
        try:
            r = requests.get(url, headers={"User-Agent": ua}, timeout=20)
            r.raise_for_status()
            if r.json().get("geometry"):
                geoms.append(shape(r.json()["geometry"]))
                log.debug("Map: got affected zone %s", url)
        except Exception:
            pass

    if not geoms:
        log.debug("Map: no geometries found – skipping")
        return None

    merged = unary_union(geoms)
    min_lon, min_lat, max_lon, max_lat = merged.bounds

    pad_lon = max((max_lon - min_lon) * MAP_PAD_FRAC, MAP_PAD_MIN_DEG)
    pad_lat = max((max_lat - min_lat) * MAP_PAD_FRAC, MAP_PAD_MIN_DEG)
    bbox = (min_lon - pad_lon, min_lat - pad_lat, max_lon + pad_lon, max_lat + pad_lat)

    west, south, east, north = bbox
    style = cfg.get("mapbox_style")
    url = (
        f"https://api.mapbox.com/styles/v1/{style}/static/"
        f"[{west},{south},{east},{north}]/{MAP_WIDTH}x{MAP_HEIGHT}"
        f"?access_token={cfg['mapbox_token']}"
    )

    r = requests.get(url, timeout=30)
    r.raise_for_status()

    img = Image.open(BytesIO(r.content)).convert("RGBA")
    overlay = Image.new("RGBA", img.size, (0,0,0,0))
    draw = ImageDraw.Draw(overlay)

    tx = Transformer.from_crs("EPSG:4326", "EPSG:3857", always_xy=True)
    minx, miny = tx.transform(west, south)
    maxx, maxy = tx.transform(east, north)

    def px(lon, lat):
        x, y = tx.transform(lon, lat)
        return (
            (x - minx) / (maxx - minx) * MAP_WIDTH,
            (maxy - y) / (maxy - miny) * MAP_HEIGHT,
        )

    def draw_poly(p):
        pts = [px(x,y) for x,y in p.exterior.coords]
        draw.polygon(pts, fill=MAP_FILL_RGBA)
        draw.line(pts, fill=MAP_STROKE_RGBA, width=MAP_STROKE_W)

    if merged.geom_type == "Polygon":
        draw_poly(merged)
    else:
        for g in merged.geoms:
            draw_poly(g)

    img.alpha_composite(overlay)
    out = BytesIO()
    img.save(out, "PNG")
    log.debug("Map: rendered PNG")
    return out.getvalue()


# ───────────────────────  ALERT LOOP  ───────────────────────

def is_still_effective(props: dict, now: datetime) -> bool:
    if props.get("messageType","").lower() == "cancel":
        return False
    end = props.get("expires") or props.get("ends")
    if end and isoparse(end) <= now:
        return False
    return True


def run_for_zone(cfg: Dict[str, Any], zone: Dict[str, Any]):
    zone_id = zone["zone_id"]
    webhook = zone["webhooks"][0]

    state = load_state(cfg, zone_id)
    now = datetime.now(UTC)

    feats = fetch_recent_alerts(zone_id, cfg["user_agent"])
    latest = latest_by_chain(feats)

    for cid, feat in sorted(latest.items(), key=lambda kv: kv[1]["properties"]["sent"]):
        props = feat["properties"]
        active = is_still_effective(props, now)
        cleared = not active
        row = state["alerts"].get(cid)

        embed = build_embed(props, cleared)

        if row is None:
            if cleared:
                continue

            png = render_map_png(cfg, props, cfg["user_agent"])
            file = None
            if png:
                embed["image"] = {"url": f"attachment://{MAP_ATTACHMENT_FILENAME}"}
                file = (MAP_ATTACHMENT_FILENAME, png)

            msg_id = discord_post_embed(embed, webhook, file)
            state["alerts"][cid] = {
                "cap_id": props["id"],
                "discord_id": msg_id,
                "status": "posted",
                "expires_at": props.get("expires") or props.get("ends") or now.isoformat(),
            }
            log.info("[%s] Posted %s (new)", zone_id, cid)

    prune_state(state, now)
    save_state(cfg, zone_id, state)


# ─────────────────────────  main  ─────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    args = ap.parse_args()

    cfg_path, log_dir, state_dir = resolve_paths(args.config)
    tmp_cfg = json.loads(cfg_path.read_text())

    level = get_log_level(os.environ.get("NOAA_ALERTS_LOGLEVEL") or tmp_cfg.get("log_level"))
    global log
    log = setup_logging(log_dir, level)

    cfg = load_config(cfg_path, state_dir)

    log.info("Starting %s %s with config=%s", APP_NAME, __version__, cfg_path)

    for zone in cfg["zones"]:
        run_for_zone(cfg, zone)

    log.info("Run completed.")


if __name__ == "__main__":
    main()
