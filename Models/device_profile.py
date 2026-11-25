"""Stored snapshot of a device's getdevinfo / registration payload.

The original device table only keeps a serial and a status flag. This table
keeps the rest of what the terminal reports, without changing that table.
"""
import json
from datetime import datetime

from sqlalchemy import text

from database import db


def ensure_device_profile():
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS device_profile (
            serial_num VARCHAR(80) NOT NULL PRIMARY KEY,
            payload MEDIUMTEXT NULL,
            firmware VARCHAR(120) NULL,
            model_name VARCHAR(120) NULL,
            ip_address VARCHAR(64) NULL,
            user_count INT NULL,
            face_count INT NULL,
            fp_count INT NULL,
            log_count INT NULL,
            display_name VARCHAR(120) NULL,
            tz_offset DECIMAL(4,1) NULL,
            dup_window INT NULL,
            webhook_tz DECIMAL(4,1) NULL,
            updated_at DATETIME NULL
        )
    """))
    db.session.commit()
    for statement in (
        "ALTER TABLE device_profile ADD COLUMN display_name VARCHAR(120) NULL",
        "ALTER TABLE device_profile ADD COLUMN tz_offset DECIMAL(4,1) NULL",
        "ALTER TABLE device_profile ADD COLUMN dup_window INT NULL",
        "ALTER TABLE device_profile ADD COLUMN webhook_tz DECIMAL(4,1) NULL",
    ):
        try:
            db.session.execute(text(statement))
            db.session.commit()
        except Exception:
            db.session.rollback()


def _pick(payload, *names):
    lowered = {str(key).lower(): value for key, value in payload.items()}
    for name in names:
        value = lowered.get(name)
        if value not in (None, ""):
            return value
    return None


def _number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def save_device_profile(serial, payload):
    if not serial or not isinstance(payload, dict):
        return
    ensure_device_profile()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.session.execute(text("""
        INSERT INTO device_profile (
            serial_num, payload, firmware, model_name, ip_address,
            user_count, face_count, fp_count, log_count, updated_at
        ) VALUES (
            :serial_num, :payload, :firmware, :model_name, :ip_address,
            :user_count, :face_count, :fp_count, :log_count, :updated_at
        )
        ON DUPLICATE KEY UPDATE
            payload = VALUES(payload),
            firmware = VALUES(firmware),
            model_name = VALUES(model_name),
            ip_address = VALUES(ip_address),
            user_count = VALUES(user_count),
            face_count = VALUES(face_count),
            fp_count = VALUES(fp_count),
            log_count = VALUES(log_count),
            updated_at = VALUES(updated_at)
    """), {
        "serial_num": str(serial),
        "payload": json.dumps(payload, default=str)[:20000],
        "firmware": str(_pick(payload, "firmware", "fwversion", "version", "firmver") or "")[:120],
        "model_name": str(_pick(payload, "model", "modelname", "devicename", "terminaltype") or "")[:120],
        "ip_address": str(_pick(payload, "ip", "ipaddress", "devip") or "")[:64],
        "user_count": _number(_pick(payload, "usercount", "useduser", "usernum")),
        "face_count": _number(_pick(payload, "facecount", "faceused")),
        "fp_count": _number(_pick(payload, "fpcount", "fpused")),
        "log_count": _number(_pick(payload, "logcount", "alllogcount", "usedlog")),
        "updated_at": now,
    })
    db.session.commit()


def _bounded_number(value, low, high, fallback):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    if number < low or number > high:
        return fallback
    return number


def save_device_settings(serial, name, timezone_offset, duplicate_window, webhook_timezone):
    if not serial:
        return
    ensure_device_profile()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.session.execute(text("""
        INSERT INTO device_profile (
            serial_num, display_name, tz_offset, dup_window, webhook_tz, updated_at
        ) VALUES (
            :serial_num, :display_name, :tz_offset, :dup_window, :webhook_tz, :updated_at
        )
        ON DUPLICATE KEY UPDATE
            display_name = VALUES(display_name),
            tz_offset = VALUES(tz_offset),
            dup_window = VALUES(dup_window),
            webhook_tz = VALUES(webhook_tz),
            updated_at = VALUES(updated_at)
    """), {
        "serial_num": str(serial)[:80],
        "display_name": str(name or "").strip()[:120],
        "tz_offset": _bounded_number(timezone_offset, -14, 14, 5.5),
        "dup_window": int(_bounded_number(duplicate_window, 0, 86400, 60)),
        "webhook_tz": _bounded_number(webhook_timezone, -14, 14, 5.5),
        "updated_at": now,
    })
    db.session.commit()


def save_device_name(serial, name):
    if not serial:
        return
    ensure_device_profile()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.session.execute(text("""
        INSERT INTO device_profile (serial_num, display_name, updated_at)
        VALUES (:serial_num, :display_name, :updated_at)
        ON DUPLICATE KEY UPDATE
            display_name = VALUES(display_name),
            updated_at = VALUES(updated_at)
    """), {
        "serial_num": str(serial)[:80],
        "display_name": str(name or "").strip()[:120],
        "updated_at": now,
    })
    db.session.commit()


def load_device_profiles():
    ensure_device_profile()
    rows = db.session.execute(text("""
        SELECT serial_num, payload, firmware, model_name, ip_address,
               user_count, face_count, fp_count, log_count, display_name,
               tz_offset, dup_window, webhook_tz, updated_at
        FROM device_profile
    """)).mappings().all()
    profiles = {}
    for row in rows:
        extra = {}
        try:
            extra = json.loads(row["payload"] or "{}")
        except (TypeError, ValueError):
            extra = {}
        profiles[row["serial_num"]] = {
            "firmware": row["firmware"] or "",
            "model": row["model_name"] or "",
            "ipAddress": row["ip_address"] or "",
            "userCount": row["user_count"],
            "faceCount": row["face_count"],
            "fingerprintCount": row["fp_count"],
            "logCount": row["log_count"],
            "displayName": row["display_name"] or "",
            "timezoneOffset": None if row["tz_offset"] is None else float(row["tz_offset"]),
            "duplicateWindow": None if row["dup_window"] is None else int(row["dup_window"]),
            "webhookTimezone": None if row["webhook_tz"] is None else float(row["webhook_tz"]),
            "updatedAt": str(row["updated_at"] or ""),
            "raw": {key: value for key, value in extra.items() if key not in ("record", "image")},
        }
    return profiles
