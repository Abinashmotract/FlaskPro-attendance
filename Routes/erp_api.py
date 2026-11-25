"""JSON API the ERP calls. The device still talks WebSocket on /pub/chat."""
import base64
import hmac
import json
import os
import re
from datetime import datetime

from flask import Blueprint, Response, g, jsonify, request

from Models.AccessDay import get_all_access_days
from Models.Device import get_all_devices, get_device_by_serial_num, insert_device
from Models.EnrollInfo import get_all_enroll_info, insert_enroll_info
from Models.MachineCommand import MachineCommand
from Models.Person import delete_person_by_id, insert_person, select_all, select_person_by_id, update_person_by_id
from Models.Records import select_all_records
from Services.erp_bridge import (
    build_erp_punch,
    deliver_punch,
    erp_settings,
    load_webhooks,
    save_webhooks,
    webhook_summary,
)
from database import db
from web_socket.WebSocketPool import ws_device

erp_api = Blueprint("erp_api", __name__, url_prefix="/api")


def _unauthorized():
    if request.method == "OPTIONS":
        return None
    if request.path in ("/api/auth/login", "/api/auth/signup"):
        return None
    from Services.portal_auth import user_from_token
    token = request.headers.get("X-Portal-Token", "")
    if token:
        user = user_from_token(token)
        if not user:
            return jsonify({"ok": False, "message": "Sign in again."}), 401
        g.portal_user = user
        return None
    expected = erp_settings()["gateway_secret"]
    if not expected:
        g.portal_user = {"id": "gateway", "name": "Gateway key", "email": "", "role": "admin"}
        return None
    given = request.headers.get("X-Gateway-Secret", "")
    if not hmac.compare_digest(str(given), expected):
        return jsonify({"ok": False, "message": "Invalid gateway secret"}), 401
    g.portal_user = {"id": "gateway", "name": "Gateway key", "email": "", "role": "admin"}
    return None


@erp_api.before_request
def cors_preflight():
    if request.method == "OPTIONS":
        return ("", 204)


@erp_api.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Gateway-Secret, X-Portal-Token, Accept"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    try:
        from Services.portal_auth import note_request
        note_request(response.status_code)
    except Exception:
        pass
    return response


VERIFY_LABELS = {
    0: "Fingerprint",
    1: "Password",
    2: "Card",
    3: "Card",
    4: "Fingerprint",
    5: "Card",
    8: "Face",
    15: "Face",
}


def backup_label(backupnum):
    try:
        number = int(backupnum)
    except (TypeError, ValueError):
        return "Template"
    if number == 50:
        return "Face"
    if number == 11:
        return "Card"
    if number == 10:
        return "Password"
    if 0 <= number <= 9:
        return f"Fingerprint {number}"
    return f"Template {number}"


def verify_label(mode):
    try:
        return VERIFY_LABELS.get(int(mode), f"Mode {mode}")
    except (TypeError, ValueError):
        return ""


def person_profiles():
    people = {person.id: person for person in select_all()}
    enrolled = {}
    photos = set()
    for info in get_all_enroll_info():
        enrolled.setdefault(info.enroll_id, []).append(info.backupnum)
        if info.backupnum == 50 and info.signatures:
            photos.add(info.enroll_id)
    return people, enrolled, photos


def profile_for(enroll_id, people, enrolled, photos):
    try:
        key = int(enroll_id)
    except (TypeError, ValueError):
        key = enroll_id
    person = people.get(key)
    labels = [backup_label(item) for item in enrolled.get(key, [])]
    return {
        "name": person.name if person else "",
        "privilege": ("Admin" if person.roll_id else "User") if person else "",
        "enrolled": labels,
        "hasPhoto": key in photos,
    }


def face_jpeg(enroll_id):
    from Models.EnrollInfo import EnrollInfo
    info = (
        db.session.query(EnrollInfo)
        .filter_by(enroll_id=int(enroll_id), backupnum=50)
        .first()
    )
    raw = str(info.signatures or "") if info else ""
    if "," in raw and raw.strip().startswith("data:"):
        raw = raw.split(",", 1)[1]
    if not raw.strip():
        return None
    try:
        return base64.b64decode(raw)
    except Exception:
        return None


def database_error(error):
    db.session.rollback()
    return jsonify({
        "ok": False,
        "database": False,
        "message": "Fingerprint database is not reachable. Fix the MySQL user in config/set.conf, then restart the gateway.",
        "error": type(error).__name__,
    }), 503


def queue_command(device_sn, name, content):
    command = MachineCommand(
        content=content if isinstance(content, str) else json.dumps(content),
        name=name,
        status=0,
        send_status=0,
        err_count=0,
        serial=device_sn,
    )
    command.insert_machine_command(command)
    return command.id


@erp_api.get("/settings/webhook")
def read_webhook():
    denied = _unauthorized()
    if denied:
        return denied
    summary = webhook_summary()
    chosen = next((item for item in summary["endpoints"] if item.get("active") and item.get("url")), None)
    return jsonify({
        "ok": True,
        "attendanceUrl": chosen.get("url") if chosen else "",
        "webhookSecret": chosen.get("authSecret") if chosen else "",
        "forwarding": summary["forwarding"],
        "mode": summary["mode"],
        "configured": summary["configured"],
        "active": summary["active"],
    })


@erp_api.post("/settings/webhook")
def write_webhook():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    url = str(data.get("attendanceUrl") or data.get("url") or "").strip()
    secret = str(data.get("webhookSecret") or data.get("secret") or "")
    store = load_webhooks()
    if url:
        store["mode"] = "external"
        if store["endpoints"]:
            store["endpoints"][0]["url"] = url
            store["endpoints"][0]["authSecret"] = secret
            store["endpoints"][0]["authType"] = "header" if secret else "none"
            store["endpoints"][0]["active"] = True
        else:
            store["endpoints"].append({
                "name": "ERP attendance",
                "url": url,
                "authSecret": secret,
                "authType": "header" if secret else "none",
                "active": True,
            })
    else:
        store["mode"] = "direct"
    saved = save_webhooks(store)
    summary = webhook_summary(saved)
    return jsonify({"ok": True, "attendanceUrl": url, "webhookSecret": secret, "forwarding": summary["forwarding"]})


@erp_api.get("/webhooks")
def list_webhooks():
    denied = _unauthorized()
    if denied:
        return denied
    return jsonify({"ok": True, **webhook_summary()})


@erp_api.put("/webhooks/mode")
def set_webhook_mode():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    store = load_webhooks()
    store["mode"] = "direct" if data.get("mode") == "direct" else "external"
    saved = save_webhooks(store)
    return jsonify({"ok": True, **webhook_summary(saved)})


@erp_api.post("/webhooks")
def create_webhook():
    denied = _unauthorized()
    if denied:
        return denied
    store = load_webhooks()
    store["endpoints"].append(request.get_json(silent=True) or {})
    saved = save_webhooks(store)
    return jsonify({"ok": True, "endpoint": saved["endpoints"][-1], **webhook_summary(saved)})


@erp_api.put("/webhooks/<endpoint_id>")
def update_webhook(endpoint_id):
    denied = _unauthorized()
    if denied:
        return denied
    store = load_webhooks()
    found = False
    incoming = request.get_json(silent=True) or {}
    incoming["id"] = endpoint_id
    for index, item in enumerate(store["endpoints"]):
        if item.get("id") == endpoint_id:
            store["endpoints"][index] = incoming
            found = True
            break
    if not found:
        return jsonify({"ok": False, "message": "Webhook not found"}), 404
    saved = save_webhooks(store)
    summary = webhook_summary(saved)
    endpoint = next(item for item in summary["endpoints"] if item["id"] == endpoint_id)
    return jsonify({"ok": True, "endpoint": endpoint, **summary})


@erp_api.delete("/webhooks/<endpoint_id>")
def delete_webhook(endpoint_id):
    denied = _unauthorized()
    if denied:
        return denied
    store = load_webhooks()
    store["endpoints"] = [item for item in store["endpoints"] if item.get("id") != endpoint_id]
    saved = save_webhooks(store)
    return jsonify({"ok": True, **webhook_summary(saved)})


@erp_api.post("/webhooks/<endpoint_id>/test")
def test_webhook(endpoint_id):
    denied = _unauthorized()
    if denied:
        return denied
    store = load_webhooks()
    endpoint = next((item for item in store["endpoints"] if item.get("id") == endpoint_id), None)
    if not endpoint:
        return jsonify({"ok": False, "message": "Webhook not found"}), 404
    sample = {
        "device_serial_num": "AYTC03020022",
        "enroll_id": 1,
        "records_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": 8,
        "intOut": 0,
        "event": 0,
        "temperature": 36.5,
    }
    try:
        result = deliver_punch(endpoint, sample, "attendance", honor_retries=True)
    except Exception as error:
        return jsonify({"ok": False, "message": str(error)}), 502
    return jsonify({"ok": result["ok"], "status": result["status"]})


@erp_api.post("/auth/signup")
def auth_signup():
    data = request.get_json(silent=True) or {}
    from Services.portal_auth import signup
    try:
        user, token = signup(data.get("name"), data.get("email"), data.get("password"))
    except ValueError as error:
        return jsonify({"ok": False, "message": str(error)}), 400
    g.portal_user = user
    return jsonify({"ok": True, "token": token, "user": user}), 201


@erp_api.post("/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    from Services.portal_auth import login
    try:
        user, token = login(data.get("email"), data.get("password"))
    except ValueError as error:
        return jsonify({"ok": False, "message": str(error)}), 401
    g.portal_user = user
    return jsonify({"ok": True, "token": token, "user": user})


@erp_api.post("/auth/logout")
def auth_logout():
    denied = _unauthorized()
    if denied:
        return denied
    from Services.portal_auth import logout
    logout(request.headers.get("X-Portal-Token", ""))
    return jsonify({"ok": True})


@erp_api.get("/auth/me")
def auth_me():
    denied = _unauthorized()
    if denied:
        return denied
    user = getattr(g, "portal_user", None)
    if not user or user.get("id") == "gateway":
        return jsonify({"ok": False, "message": "Sign in again."}), 401
    return jsonify({"ok": True, "user": user})


@erp_api.get("/audit")
def list_audit_route():
    denied = _unauthorized()
    if denied:
        return denied
    from Services.portal_auth import current_user, list_audit
    actor = current_user()
    rows = list_audit(
        actor,
        module=request.args.get("module") or "",
        role=request.args.get("role") or "",
        user_query=request.args.get("q") or "",
    )
    modules = ["Auth", "Dashboard", "Attendance", "People", "Devices", "Communication", "Access", "Settings", "API Docs", "Audit", "Gateway"]
    return jsonify({"ok": True, "logs": rows, "modules": modules, "role": (actor or {}).get("role") or ""})


@erp_api.post("/audit")
def add_audit_route():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    from Services.portal_auth import current_user, record_audit
    module = str(data.get("module") or "Gateway").strip()[:40]
    action = str(data.get("action") or "Opened a page").strip()[:80]
    detail = str(data.get("detail") or module).strip()[:240]
    record_audit(current_user(), module, action, detail, 200)
    return jsonify({"ok": True}), 201


@erp_api.get("/health")
def health():
    denied = _unauthorized()
    if denied:
        return denied
    summary = webhook_summary()
    from Services.portal_live import prune_offline_devices
    prune_offline_devices()
    return jsonify({
        "ok": True,
        "service": "device-gateway",
        "websocket": "/pub/chat",
        "onlineDevices": len(ws_device),
        "erpForwarding": summary["forwarding"],
    })


@erp_api.get("/devices")
def list_devices():
    denied = _unauthorized()
    if denied:
        return denied
    devices = []
    database_ok = True
    database_message = ""
    profiles = {}
    try:
        stored_devices = get_all_devices()
        from Models.device_profile import load_device_profiles
        profiles = load_device_profiles()
    except Exception as error:
        db.session.rollback()
        stored_devices = []
        database_ok = False
        database_message = "Fingerprint database is not reachable."
        print("device list database error", type(error).__name__)
    licenses = load_device_licenses()
    from Services.portal_live import prune_offline_devices
    prune_offline_devices()
    for device in stored_devices:
        serial = device.serial_num
        live = ws_device.get(serial)
        live_sock = live.get("websocket") if isinstance(live, dict) else getattr(live, "websocket", None)
        online = live_sock is not None and getattr(live_sock, "connected", True) is not False
        devices.append({
            "id": device.id,
            "serialNumber": serial,
            "status": device.status,
            "online": online,
            "licenseSaved": serial in licenses,
            "profile": profiles.get(serial) or {},
        })
    for serial, live in ws_device.items():
        if any(item["serialNumber"] == serial for item in devices):
            continue
        devices.append({
            "id": None,
            "serialNumber": serial,
            "status": 1,
            "online": True,
            "licenseSaved": serial in licenses,
            "profile": profiles.get(serial) or {},
        })
    return jsonify({
        "ok": True,
        "devices": devices,
        "database": database_ok,
        "message": database_message,
    })


def _license_path():
    from config.readConf import readConf
    return os.path.join(os.path.dirname(readConf().conf_path()), "device_licenses.json")


def load_device_licenses():
    path = _license_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        return {}
    return stored if isinstance(stored, dict) else {}


def save_device_license(serial, key):
    stored = load_device_licenses()
    stored[serial] = {"savedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    path = _license_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(stored, handle, indent=2)
        handle.write("\n")
    secret_path = path.replace("device_licenses.json", "device_license_keys.json")
    keys = {}
    if os.path.isfile(secret_path):
        try:
            with open(secret_path, encoding="utf-8") as handle:
                keys = json.load(handle)
        except (OSError, ValueError):
            keys = {}
    if not isinstance(keys, dict):
        keys = {}
    keys[serial] = key
    with open(secret_path, "w", encoding="utf-8") as handle:
        json.dump(keys, handle)
        handle.write("\n")


def serial_from_license(text):
    raw = str(text or "").strip()
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        for key in ("serial", "serialNumber", "sn", "deviceSn", "device_sn"):
            if parsed.get(key):
                return str(parsed.get(key)).strip().upper()
    match = re.search(r"\b(?:AYTC|TFS)[A-Z0-9-]{6,}\b", raw, re.I)
    if match:
        return match.group(0).upper()
    match = re.search(r"\b[A-Z]{2,8}\d{6,}\b", raw, re.I)
    if match:
        return match.group(0).upper()
    return ""


def register_device_serial(serial):
    clean = str(serial or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9-]{4,40}", clean):
        return None, False, "Enter the serial from the label on the device."
    existing = get_device_by_serial_num(clean)
    if existing:
        return existing, False, ""
    insert_device(clean, 0)
    return get_device_by_serial_num(clean), True, ""


@erp_api.post("/devices")
def add_device():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    serial = data.get("serialNumber") or data.get("deviceSn") or data.get("serial")
    try:
        device, created, message = register_device_serial(serial)
    except Exception:
        db.session.rollback()
        return jsonify({"ok": False, "message": "Could not save the device."}), 500
    if not device:
        return jsonify({"ok": False, "message": message}), 400
    return jsonify({
        "ok": True,
        "serialNumber": device.serial_num,
        "created": created,
        "message": "Device added. It stays offline until that terminal connects." if created else "Device is already on this gateway.",
    })


@erp_api.post("/devices/license")
def activate_device_license():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    key = str(data.get("licenseKey") or "").strip()
    if len(key) < 8:
        return jsonify({"ok": False, "message": "Paste the license key first."}), 400
    serial = serial_from_license(key)
    if not serial:
        return jsonify({"ok": False, "message": "This key does not include a device serial. Add the device by serial number instead."}), 400
    try:
        device, _created, message = register_device_serial(serial)
        if not device:
            return jsonify({"ok": False, "message": message}), 400
        save_device_license(device.serial_num, key)
    except Exception:
        db.session.rollback()
        return jsonify({"ok": False, "message": "Could not activate this license."}), 500
    return jsonify({"ok": True, "serialNumber": device.serial_num, "message": f"License saved for {device.serial_num}."})


@erp_api.post("/commands")
def create_command():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or data.get("serialNumber") or "").strip()
    name = str(data.get("name") or data.get("cmd") or "").strip()
    content = data.get("content")
    if not device_sn or not name:
        return jsonify({"ok": False, "message": "deviceSn and name are required"}), 400
    if content is None:
        payload = {"cmd": name}
        payload.update(data.get("payload") or {})
        content = json.dumps(payload)
    elif not isinstance(content, str):
        content = json.dumps(content)
    command_id = queue_command(device_sn, name, content)
    return jsonify({"ok": True, "id": command_id, "deviceSn": device_sn, "name": name}), 201


@erp_api.post("/persons")
def save_person():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    try:
        enroll_id = int(data.get("enrollId"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "enrollId is required"}), 400
    name = str(data.get("name") or "").strip()
    privilege = int(data.get("privilege") or 0)
    if not select_person_by_id(enroll_id):
        insert_person(id=enroll_id, name=name or str(enroll_id), roll_id=privilege)
    else:
        update_person_by_id(enroll_id, name=name or str(enroll_id), roll_id=privilege)

    saved = []
    templates = [
        (10, data.get("password")),
        (11, data.get("cardNum")),
        (50, data.get("faceBase64")),
    ]
    for backupnum, value in templates:
        if value in (None, ""):
            continue
        insert_enroll_info(backupnum=backupnum, enroll_id=enroll_id, signatures=str(value))
        saved.append(backupnum)

    pushed = None
    device_sn = str(data.get("deviceSn") or "").strip()
    if data.get("push") and device_sn:
        backupnum = int(data.get("backupNum") if data.get("backupNum") is not None else (saved[-1] if saved else -1))
        record = data.get("faceBase64") or data.get("cardNum") or data.get("password") or ""
        pushed = _queue_user(device_sn, enroll_id, name, backupnum, privilege, record)
    return jsonify({"ok": True, "enrollId": enroll_id, "savedBackupNums": saved, "commandId": pushed}), 201


def _queue_user(device_sn, enroll_id, name, backupnum, privilege, record):
    if int(backupnum) == -1:
        payload = {
            "cmd": "setusername",
            "count": 1,
            "record": [{"enrollid": int(enroll_id), "name": name or str(enroll_id)}],
        }
        return queue_command(device_sn, "setusername", json.dumps(payload))
    payload = {
        "cmd": "setuserinfo",
        "enrollid": int(enroll_id),
        "name": name or str(enroll_id),
        "backupnum": int(backupnum),
        "admin": int(privilege or 0),
        "record": record,
    }
    return queue_command(device_sn, "setuserinfo", json.dumps(payload))


@erp_api.post("/persons/push")
def push_person():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    try:
        enroll_id = int(data.get("enrollId"))
        backupnum = int(data.get("backupNum"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "enrollId, backupNum and deviceSn are required"}), 400
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    person = select_person_by_id(enroll_id)
    name = data.get("name") or (person.name if person else str(enroll_id))
    privilege = int(data.get("privilege") or (person.roll_id if person else 0))
    record = data.get("record") or ""
    command_id = _queue_user(device_sn, enroll_id, name, backupnum, privilege, record)
    return jsonify({"ok": True, "id": command_id}), 201


@erp_api.post("/persons/delete")
def delete_person():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    try:
        enroll_id = int(data.get("enrollId"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "enrollId is required"}), 400
    removed = False
    if data.get("local", True) and select_person_by_id(enroll_id):
        delete_person_by_id(enroll_id)
        removed = True
    command_id = None
    if device_sn:
        payload = {"cmd": "deleteuser", "enrollid": enroll_id, "backupnum": 13}
        command_id = queue_command(device_sn, "deleteuser", json.dumps(payload))
    if not removed and not command_id:
        return jsonify({"ok": False, "message": "Person was not on this gateway."}), 404
    return jsonify({"ok": True, "id": command_id, "removed": removed}), 201


@erp_api.post("/logs/pull")
def pull_logs():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    full = bool(data.get("full"))
    payload = {"cmd": "getalllog" if full else "getnewlog", "stn": True}
    command_id = queue_command(device_sn, payload["cmd"], json.dumps(payload))
    return jsonify({"ok": True, "id": command_id, "cmd": payload["cmd"]}), 201


@erp_api.post("/door/open")
def open_door():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    door_num = int(data.get("doorNum") or 1)
    payload = {"cmd": "opendoor", "doornum": door_num}
    command_id = queue_command(device_sn, "opendoor", json.dumps(payload))
    try:
        from Services.erp_bridge import forward_gateway_event
        forward_gateway_event("door_event", device_sn, {"doorNumber": door_num})
    except Exception:
        pass
    return jsonify({"ok": True, "id": command_id}), 201


@erp_api.get("/records")
def list_records():
    denied = _unauthorized()
    if denied:
        return denied
    limit = min(max(int(request.args.get("limit") or 50), 1), 200)
    try:
        rows = list(reversed(select_all_records()))[:limit]
        people, enrolled, photos = person_profiles()
    except Exception as error:
        return database_error(error)
    records = []
    for row in rows:
        item = row.to_dict()
        item.update(profile_for(row.enroll_id, people, enrolled, photos))
        item["verifyMethod"] = verify_label(row.mode)
        records.append(item)
    return jsonify({
        "ok": True,
        "records": records,
        "serverTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


@erp_api.get("/dashboard")
def dashboard():
    denied = _unauthorized()
    if denied:
        return denied
    settings = erp_settings()
    database_ok = True
    people = 0
    punches = 0
    today_punches = 0
    recent = []
    try:
        people = len(select_all())
        stored = select_all_records()
        punches = len(stored)
        today = datetime.now().strftime("%Y-%m-%d")
        today_punches = sum(1 for row in stored if str(row.records_time).startswith(today))
        profiles, enrolled, photos = person_profiles()
        for row in list(reversed(stored))[:6]:
            item = row.to_dict()
            item.update(profile_for(row.enroll_id, profiles, enrolled, photos))
            item["verifyMethod"] = verify_label(row.mode)
            recent.append(item)
    except Exception as error:
        db.session.rollback()
        database_ok = False
        print("dashboard database error", type(error).__name__)
    from Services.portal_live import prune_offline_devices
    prune_offline_devices()
    online = len(ws_device)
    return jsonify({
        "ok": True,
        "database": database_ok,
        "onlineDevices": online,
        "people": people,
        "punches": punches,
        "todayPunches": today_punches,
        "recent": recent,
        "erpForwarding": bool(settings["attendance_url"]),
        "websocketPath": "/pub/chat",
        "serverTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


@erp_api.get("/persons")
def list_persons():
    denied = _unauthorized()
    if denied:
        return denied
    try:
        people = select_all()
        enrolls = get_all_enroll_info()
    except Exception as error:
        return database_error(error)
    by_enroll = {}
    photos = set()
    for info in enrolls:
        by_enroll.setdefault(info.enroll_id, []).append(info.backupnum)
        if info.backupnum == 50 and info.signatures:
            photos.add(info.enroll_id)
    return jsonify({
        "ok": True,
        "persons": [{
            "enrollId": person.id,
            "name": person.name,
            "privilege": person.roll_id,
            "backupNums": by_enroll.get(person.id, []),
            "enrolled": [backup_label(item) for item in by_enroll.get(person.id, [])],
            "hasPhoto": person.id in photos,
        } for person in people],
    })


@erp_api.get("/persons/<int:enroll_id>/photo")
def person_photo(enroll_id):
    denied = _unauthorized()
    if denied:
        return denied
    try:
        image = face_jpeg(enroll_id)
    except Exception as error:
        return database_error(error)
    if not image:
        return jsonify({"ok": False, "message": "No face photo for this enroll id"}), 404
    return Response(image, mimetype="image/jpeg")


@erp_api.get("/commands")
def list_commands():
    denied = _unauthorized()
    if denied:
        return denied
    try:
        rows = (
            db.session.query(MachineCommand)
            .order_by(MachineCommand.id.desc())
            .limit(40)
            .all()
        )
    except Exception as error:
        return database_error(error)
    return jsonify({
        "ok": True,
        "commands": [{
            "id": row.id,
            "serialNumber": row.serial,
            "name": row.name,
            "status": row.status,
            "sendStatus": row.send_status,
            "errorCount": row.err_count,
            "createdAt": str(row.gmt_crate),
        } for row in rows],
    })


@erp_api.get("/access-days")
def list_access_days():
    denied = _unauthorized()
    if denied:
        return denied
    try:
        rows = get_all_access_days()
    except Exception as error:
        return database_error(error)
    return jsonify({"ok": True, "accessDays": [row.to_dict() for row in rows]})


@erp_api.post("/devices/time")
def sync_device_time():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = {"cmd": "settime", "time": now}
    command_id = queue_command(device_sn, "settime", json.dumps(payload))
    return jsonify({"ok": True, "id": command_id, "time": now}), 201


@erp_api.post("/devices/reboot")
def reboot_device():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    command_id = queue_command(device_sn, "reboot", json.dumps({"cmd": "reboot"}))
    return jsonify({"ok": True, "id": command_id}), 201


@erp_api.post("/devices/name")
def rename_device():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    from Models.device_profile import save_device_name
    save_device_name(device_sn, data.get("name") or "")
    return jsonify({"ok": True, "deviceSn": device_sn, "name": str(data.get("name") or "").strip()})


@erp_api.post("/devices/settings")
def save_device_settings_route():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    from Models.device_profile import save_device_settings
    save_device_settings(
        device_sn,
        data.get("name") or "",
        data.get("timezoneOffset"),
        data.get("duplicateWindow"),
        data.get("webhookTimezone"),
    )
    return jsonify({"ok": True, "deviceSn": device_sn})


@erp_api.post("/devices/info")
def ask_device_info():
    denied = _unauthorized()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    device_sn = str(data.get("deviceSn") or "").strip()
    if not device_sn:
        return jsonify({"ok": False, "message": "deviceSn is required"}), 400
    command_id = queue_command(device_sn, "getdevinfo", json.dumps({"cmd": "getdevinfo"}))
    return jsonify({"ok": True, "id": command_id}), 201
