"""Forward device punches and presence events to attendance webhooks."""
import base64
import hashlib
import hmac
import json
import os
import time
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from config.readConf import readConf

EVENT_NAMES = ("attendance", "device_online", "device_offline", "door_event")
AUTH_TYPES = ("none", "bearer", "basic", "apikey", "header")
MODE_NAMES = {
    0: "Fingerprint",
    1: "Password",
    2: "Card",
    3: "Card",
    4: "Fingerprint",
    5: "Card",
    8: "Face",
    15: "Face",
}


def load_gateway_env():
    """Load FlaskProject/.env. A real process environment variable wins."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


load_gateway_env()


def _write_env_value(key, value):
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    lines = []
    if os.path.isfile(env_path):
        with open(env_path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    prefix = f"{key}="
    replaced = False
    next_lines = []
    for line in lines:
        if line.startswith(prefix):
            next_lines.append(prefix + value)
            replaced = True
        else:
            next_lines.append(line)
    if not replaced:
        next_lines.append(prefix + value)
    with open(env_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(next_lines) + "\n")


def _write_conf_value(key, value):
    path = readConf().conf_path()
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    prefix = f"{key}"
    next_lines = []
    replaced = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(prefix) and "=" in stripped.split("#", 1)[0]:
            next_lines.append(f"{key} = {value}")
            replaced = True
        else:
            next_lines.append(line)
    if not replaced:
        next_lines.extend(["", f"{key} = {value}"])
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(next_lines) + "\n")


def _webhook_path():
    return os.path.join(os.path.dirname(readConf().conf_path()), "webhooks.json")


def _blank_endpoint(**overrides):
    endpoint = {
        "id": "wh_" + uuid.uuid4().hex[:10],
        "name": "",
        "active": True,
        "method": "POST",
        "url": "",
        "description": "",
        "contentType": "application/json",
        "events": ["attendance"],
        "deviceSerials": [],
        "authType": "none",
        "authHeader": "x-timmy-secret",
        "authSecret": "",
        "authUser": "",
        "authPassword": "",
        "customHeaders": "{}",
        "payloadTemplate": "",
        "includePhoto": False,
        "successCodes": "200,201,204",
        "responseMapping": False,
        "responseField": "",
        "responseValue": "",
        "retries": 3,
        "retryDelayMs": 1000,
        "timeoutMs": 5000,
        "timeout": 5,
        "hmacSecret": "",
        "timezoneOffset": False,
        "successCount": 0,
        "failCount": 0,
        "consecutiveFails": 0,
        "lastStatus": 0,
        "lastTriggered": "",
    }
    endpoint.update(overrides)
    return endpoint


def _whole(value, fallback, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = fallback
    return min(max(number, low), high)


def _string_list(value, limit=40):
    if not isinstance(value, list):
        return []
    cleaned = []
    for item in value:
        text = str(item or "").strip()[:80]
        if text and text not in cleaned:
            cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _clean_endpoint(raw):
    current = raw if isinstance(raw, dict) else {}
    endpoint = _blank_endpoint()
    endpoint["id"] = str(current.get("id") or endpoint["id"])[:40]
    endpoint["name"] = str(current.get("name") or "").strip()[:80]
    endpoint["active"] = bool(current.get("active", True))
    method = str(current.get("method") or "POST").upper()
    endpoint["method"] = method if method in ("POST", "PUT") else "POST"
    endpoint["url"] = str(current.get("url") or "").strip()[:500]
    endpoint["description"] = str(current.get("description") or "").strip()[:240]
    content_type = str(current.get("contentType") or "application/json").strip()
    endpoint["contentType"] = content_type if content_type in ("application/json", "application/x-www-form-urlencoded") else "application/json"
    events = [item for item in _string_list(current.get("events"), 4) if item in EVENT_NAMES]
    endpoint["events"] = events or ["attendance"]
    endpoint["deviceSerials"] = _string_list(current.get("deviceSerials"))
    auth_type = str(current.get("authType") or "none")
    endpoint["authType"] = auth_type if auth_type in AUTH_TYPES else "none"
    endpoint["authHeader"] = str(current.get("authHeader") or "x-timmy-secret").strip()[:80] or "x-timmy-secret"
    endpoint["authSecret"] = str(current.get("authSecret") or "")
    endpoint["authUser"] = str(current.get("authUser") or "").strip()[:120]
    endpoint["authPassword"] = str(current.get("authPassword") or "")
    headers = current.get("customHeaders") if isinstance(current.get("customHeaders"), str) else "{}"
    try:
        parsed = json.loads(headers or "{}")
        endpoint["customHeaders"] = json.dumps(parsed if isinstance(parsed, dict) else {})
    except ValueError:
        endpoint["customHeaders"] = "{}"
    endpoint["payloadTemplate"] = str(current.get("payloadTemplate") or "")
    endpoint["includePhoto"] = bool(current.get("includePhoto"))
    endpoint["successCodes"] = str(current.get("successCodes") or "200,201,204").strip()[:80]
    endpoint["responseMapping"] = bool(current.get("responseMapping"))
    endpoint["responseField"] = str(current.get("responseField") or "").strip()[:80]
    endpoint["responseValue"] = str(current.get("responseValue") or "").strip()[:80]
    endpoint["retries"] = _whole(current.get("retries"), 3, 0, 5)
    endpoint["retryDelayMs"] = _whole(current.get("retryDelayMs"), 1000, 0, 60000)
    endpoint["timeoutMs"] = _whole(current.get("timeoutMs"), _whole(current.get("timeout"), 8, 2, 30) * 1000, 1000, 30000)
    endpoint["timeout"] = min(max(int(round(endpoint["timeoutMs"] / 1000)), 2), 30)
    endpoint["hmacSecret"] = str(current.get("hmacSecret") or "")
    endpoint["timezoneOffset"] = bool(current.get("timezoneOffset"))
    endpoint["successCount"] = _whole(current.get("successCount"), 0, 0, 10000000)
    endpoint["failCount"] = _whole(current.get("failCount"), 0, 0, 10000000)
    endpoint["consecutiveFails"] = _whole(current.get("consecutiveFails"), 0, 0, 10000000)
    endpoint["lastStatus"] = _whole(current.get("lastStatus"), 0, 0, 999)
    endpoint["lastTriggered"] = str(current.get("lastTriggered") or "")[:32]
    return endpoint


def load_webhooks():
    path = _webhook_path()
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as handle:
                stored = json.load(handle)
        except (OSError, ValueError):
            stored = {}
        mode = stored.get("mode") if isinstance(stored, dict) else "external"
        raw_items = stored.get("endpoints") if isinstance(stored, dict) else []
        endpoints = [_clean_endpoint(item) for item in raw_items or []]
        return {"mode": "direct" if mode == "direct" else "external", "endpoints": endpoints}

    settings = erp_settings()
    endpoints = []
    if settings["attendance_url"]:
        endpoints.append(_clean_endpoint({
            "name": "ERP attendance",
            "url": settings["attendance_url"],
            "authType": "header" if settings["webhook_secret"] else "none",
            "authHeader": "x-timmy-secret",
            "authSecret": settings["webhook_secret"],
            "description": "Forwards each punch to the school ERP.",
            "active": True,
        }))
    store = {"mode": "external" if endpoints else "direct", "endpoints": endpoints}
    save_webhooks(store, sync_legacy=False)
    return store


def save_webhooks(store, sync_legacy=True):
    mode = "direct" if store.get("mode") == "direct" else "external"
    endpoints = [_clean_endpoint(item) for item in store.get("endpoints") or []]
    path = _webhook_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"mode": mode, "endpoints": endpoints}, handle, indent=2)
        handle.write("\n")
    saved = {"mode": mode, "endpoints": endpoints}
    if sync_legacy:
        _sync_legacy(saved)
    return saved


def _sync_legacy(store):
    chosen = None
    if store["mode"] == "external":
        chosen = next((item for item in store["endpoints"] if item.get("active") and item.get("url")), None)
    url = chosen.get("url") if chosen else ""
    secret = ""
    if chosen and chosen.get("authType") != "none":
        secret = chosen.get("authSecret") or ""
    save_webhook_settings(url, secret)


def webhook_summary(store=None):
    store = store or load_webhooks()
    active = [item for item in store["endpoints"] if item.get("active") and item.get("url")]
    return {
        "mode": store["mode"],
        "endpoints": store["endpoints"],
        "configured": len(store["endpoints"]),
        "active": len(active) if store["mode"] == "external" else 0,
        "forwarding": store["mode"] == "external" and bool(active),
    }


def save_webhook_settings(url, secret):
    clean_url = str(url or "").strip()
    clean_secret = str(secret or "").strip()
    _write_conf_value("attendance_url", clean_url)
    _write_conf_value("webhook_secret", clean_secret)
    _write_env_value("ERP_ATTENDANCE_URL", clean_url)
    _write_env_value("ERP_WEBHOOK_SECRET", clean_secret)
    os.environ["ERP_ATTENDANCE_URL"] = clean_url
    os.environ["ERP_WEBHOOK_SECRET"] = clean_secret
    return {"attendanceUrl": clean_url, "webhookSecret": clean_secret, "forwarding": bool(clean_url)}


def erp_settings():
    conf = {}
    try:
        conf = readConf().GetErpParam()
    except Exception:
        conf = {}
    url = os.environ.get("ERP_ATTENDANCE_URL", "").strip() or conf.get("attendance_url", "")
    secret = os.environ.get("ERP_WEBHOOK_SECRET", "").strip() or conf.get("webhook_secret", "")
    gateway_secret = os.environ.get("GATEWAY_API_SECRET", "").strip() or conf.get("gateway_secret", "")
    return {
        "attendance_url": url.strip(),
        "webhook_secret": secret.strip(),
        "gateway_secret": gateway_secret.strip(),
    }


def build_erp_punch(record):
    """Device wall clock stays a string. ERP stores it as Asia/Kolkata."""
    if not isinstance(record, dict):
        return {}
    inout = record.get("intOut")
    if inout is None:
        inout = record.get("inout", 0)
    event = record.get("event")
    return {
        "sn": str(record.get("device_serial_num") or record.get("sn") or "").strip(),
        "enrollid": record.get("enroll_id") if record.get("enroll_id") is not None else record.get("enrollid"),
        "time": str(record.get("records_time") or record.get("time") or "").strip(),
        "mode": record.get("mode") if record.get("mode") is not None else 0,
        "inout": inout if inout is not None else 0,
        "event": event if event is not None else 0,
    }


def _shift_clock(value, hours):
    try:
        parsed = datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value or "")
    return (parsed - timedelta(hours=float(hours))).strftime("%Y-%m-%d %H:%M:%S")


def _unix_clock(value):
    try:
        return int(datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S").timestamp())
    except ValueError:
        return 0


def _device_hours(serial):
    try:
        from Models.device_profile import load_device_profiles
        profile = (load_device_profiles() or {}).get(serial) or {}
        hours = profile.get("webhookTimezone")
        if hours is None:
            hours = profile.get("timezoneOffset")
        return float(5.5 if hours is None else hours)
    except Exception:
        return 5.5


def _context(record, endpoint, event_name):
    punch = build_erp_punch(record if isinstance(record, dict) else {})
    local_time = punch.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stamp = local_time
    if endpoint.get("timezoneOffset"):
        stamp = _shift_clock(local_time, _device_hours(punch.get("sn")))
    try:
        mode = int(punch.get("mode") or 0)
    except (TypeError, ValueError):
        mode = 0
    photo = ""
    if isinstance(record, dict):
        photo = str(record.get("_photo") or "")
    door = ""
    if isinstance(record, dict) and record.get("doorNumber") not in (None, ""):
        door = record.get("doorNumber")
    temperature = ""
    if isinstance(record, dict) and record.get("temperature") not in (None, ""):
        temperature = record.get("temperature")
    context = {
        "sn": punch.get("sn") or "",
        "enrollid": punch.get("enrollid") if punch.get("enrollid") is not None else "",
        "time": stamp,
        "mode": mode,
        "inout": punch.get("inout") if punch.get("inout") is not None else 0,
        "event": punch.get("event") if event_name == "attendance" else event_name,
        "enrollId": punch.get("enrollid") if punch.get("enrollid") is not None else "",
        "timestamp": stamp,
        "timestampLocal": local_time,
        "timestampUnix": _unix_clock(local_time),
        "deviceSerial": punch.get("sn") or "",
        "modeName": MODE_NAMES.get(mode, str(mode)),
        "doorNumber": door,
        "inOut": punch.get("inout") if punch.get("inout") is not None else 0,
        "temperature": temperature,
        "hasPhoto": bool(photo or (isinstance(record, dict) and record.get("image"))),
        "logId": (record or {}).get("id") if isinstance(record, dict) else "",
        "eventName": event_name,
    }
    if endpoint.get("includePhoto") and photo:
        context["photo"] = photo
    return context


def _render(template, context):
    rendered = template
    for key, value in context.items():
        token = "{{" + str(key) + "}}"
        rendered = rendered.replace('"' + token + '"', json.dumps(value, ensure_ascii=False))
        if isinstance(value, str):
            safe = json.dumps(value, ensure_ascii=False)[1:-1]
        else:
            safe = json.dumps(value, ensure_ascii=False)
        rendered = rendered.replace(token, safe)
    return rendered


def _payload_for(endpoint, record, event_name="attendance"):
    context = _context(record, endpoint, event_name)
    template = (endpoint.get("payloadTemplate") or "").strip()
    if not template:
        if event_name == "attendance":
            body = {
                "sn": context["sn"],
                "enrollid": context["enrollid"],
                "time": context["time"],
                "mode": context["mode"],
                "inout": context["inout"],
                "event": context["event"],
            }
        else:
            body = {
                "event": event_name,
                "deviceSerial": context["deviceSerial"],
                "timestamp": context["timestamp"],
                "doorNumber": context["doorNumber"],
            }
        if context.get("photo"):
            body["photo"] = context["photo"]
        if endpoint.get("contentType") == "application/x-www-form-urlencoded":
            from urllib.parse import urlencode
            return urlencode({key: "" if value is None else value for key, value in body.items()}).encode("utf-8")
        return json.dumps(body).encode("utf-8")
    rendered = _render(template, context)
    if endpoint.get("contentType") == "application/json":
        json.loads(rendered)
    return rendered.encode("utf-8")


def _success_codes(endpoint):
    codes = set()
    for part in str(endpoint.get("successCodes") or "").split(","):
        part = part.strip()
        if part.isdigit():
            codes.add(int(part))
    return codes or {200, 201, 204}


def _headers_for(endpoint, body, event_name):
    headers = {
        "Content-Type": endpoint.get("contentType") or "application/json",
        "Accept": "application/json",
        "x-webhook-event": event_name,
    }
    try:
        extra = json.loads(endpoint.get("customHeaders") or "{}")
    except ValueError:
        extra = {}
    if isinstance(extra, dict):
        for key, value in extra.items():
            name = str(key or "").strip()
            if name and name.lower() not in ("host", "content-length"):
                headers[name] = str(value)
    auth_type = endpoint.get("authType")
    secret = endpoint.get("authSecret") or ""
    if auth_type == "bearer" and secret:
        headers["Authorization"] = "Bearer " + secret
    elif auth_type == "basic":
        token = base64.b64encode(f"{endpoint.get('authUser') or ''}:{endpoint.get('authPassword') or ''}".encode()).decode()
        headers["Authorization"] = "Basic " + token
    elif auth_type == "apikey" and secret:
        headers[endpoint.get("authHeader") or "X-API-Key"] = secret
    elif auth_type == "header" and secret:
        headers[endpoint.get("authHeader") or "x-timmy-secret"] = secret
    hmac_secret = endpoint.get("hmacSecret") or ""
    if hmac_secret:
        stamp = str(int(time.time()))
        digest = hmac.new(hmac_secret.encode("utf-8"), (stamp + ".").encode("utf-8") + body, hashlib.sha256).hexdigest()
        headers["X-Timy-Timestamp"] = stamp
        headers["X-Timy-Signature"] = digest
    return headers


def _response_matches(endpoint, raw):
    if not endpoint.get("responseMapping"):
        return True
    field = endpoint.get("responseField") or ""
    if not field:
        return True
    try:
        body = json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        return False
    current = body
    for part in field.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = None
            break
    expected = endpoint.get("responseValue") or ""
    return str(current if current is not None else "") == expected


def _note_delivery(endpoint_id, ok, status):
    if not endpoint_id:
        return
    try:
        store = load_webhooks()
        for item in store["endpoints"]:
            if item.get("id") != endpoint_id:
                continue
            item["lastStatus"] = int(status or 0)
            item["lastTriggered"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if ok:
                item["successCount"] = int(item.get("successCount") or 0) + 1
                item["consecutiveFails"] = 0
            else:
                item["failCount"] = int(item.get("failCount") or 0) + 1
                item["consecutiveFails"] = int(item.get("consecutiveFails") or 0) + 1
            break
        save_webhooks(store, sync_legacy=False)
    except Exception as error:
        print("[erp_bridge] could not store webhook result:", error)


def _deliver_once(endpoint, body, event_name, timeout):
    request = urllib.request.Request(
        endpoint["url"],
        data=body,
        headers=_headers_for(endpoint, body, event_name),
        method=endpoint.get("method") or "POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = error.code
    ok = status in _success_codes(endpoint) and _response_matches(endpoint, raw)
    return {"ok": ok, "status": status}


def deliver_punch(endpoint, record, event_name="attendance", honor_retries=True):
    body = _payload_for(endpoint, record, event_name)
    retries = int(endpoint.get("retries") or 0)
    delay = int(endpoint.get("retryDelayMs") or 0) / 1000.0
    timeout = int(endpoint.get("timeoutMs") or 5000) / 1000.0
    if not honor_retries:
        retries = min(retries, 1)
        timeout = min(timeout, 8)
        delay = min(delay, 1)
    last = {"ok": False, "status": 0}
    for attempt in range(retries + 1):
        if attempt and delay:
            time.sleep(delay)
        try:
            last = _deliver_once(endpoint, body, event_name, timeout)
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            last = {"ok": False, "status": 0, "message": str(error)}
        if last.get("ok"):
            break
    _note_delivery(endpoint.get("id"), last.get("ok"), last.get("status"))
    return last


def _selected(endpoint, event_name, serial):
    if not endpoint.get("active") or not endpoint.get("url"):
        return False
    if event_name not in (endpoint.get("events") or ["attendance"]):
        return False
    serials = endpoint.get("deviceSerials") or []
    return not serials or serial in serials


def forward_punches_to_erp(records):
    summary = webhook_summary()
    if not summary["forwarding"] or not records:
        return {"forwarded": 0, "skipped": True}

    forwarded = 0
    errors = []
    for record in records:
        punch = build_erp_punch(record)
        if not punch.get("sn") or punch.get("enrollid") in (None, "") or not punch.get("time"):
            continue
        for endpoint in summary["endpoints"]:
            if not _selected(endpoint, "attendance", punch.get("sn")):
                continue
            try:
                result = deliver_punch(endpoint, record, "attendance", honor_retries=False)
                if result["ok"]:
                    forwarded += 1
                else:
                    errors.append(endpoint["name"] or endpoint["url"])
            except (urllib.error.URLError, ValueError, TimeoutError) as error:
                errors.append(str(error))
                print("[erp_bridge] attendance forward failed:", error)
    return {"forwarded": forwarded, "errors": errors, "skipped": False}


def forward_gateway_event(event_name, serial, extra=None):
    if event_name not in EVENT_NAMES or event_name == "attendance":
        return {"forwarded": 0, "skipped": True}
    summary = webhook_summary()
    if not summary["forwarding"] or not serial:
        return {"forwarded": 0, "skipped": True}
    record = {
        "device_serial_num": serial,
        "enroll_id": 0,
        "records_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": 0,
        "intOut": 0,
        "event": event_name,
    }
    if isinstance(extra, dict):
        record.update(extra)
    forwarded = 0
    for endpoint in summary["endpoints"]:
        if not _selected(endpoint, event_name, serial):
            continue
        try:
            result = deliver_punch(endpoint, record, event_name, honor_retries=False)
            if result["ok"]:
                forwarded += 1
        except (urllib.error.URLError, ValueError, TimeoutError) as error:
            print("[erp_bridge] event forward failed:", error)
    return {"forwarded": forwarded, "skipped": False}
