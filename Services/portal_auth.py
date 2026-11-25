"""Portal accounts, sessions, and the audit trail."""
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timedelta

from flask import g, request

from config.readConf import readConf

_LOCK = threading.Lock()
SESSION_DAYS = 14


def _config_dir():
    return os.path.dirname(readConf().conf_path())


def _users_path():
    return os.path.join(_config_dir(), "portal_users.json")


def _sessions_path():
    return os.path.join(_config_dir(), "portal_sessions.json")


def _audit_path():
    return os.path.join(_config_dir(), "audit_log.jsonl")


def _read_json(path, fallback):
    if not os.path.isfile(path):
        return fallback
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return fallback


def _write_json(path, payload):
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _public_user(user):
    return {
        "id": user.get("id") or "",
        "name": user.get("name") or "",
        "email": user.get("email") or "",
        "role": user.get("role") or "user",
    }


def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return salt, digest


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_users():
    data = _read_json(_users_path(), {"users": []})
    return data.get("users") if isinstance(data, dict) else []


def _save_users(users):
    _write_json(_users_path(), {"users": users})


def load_sessions():
    data = _read_json(_sessions_path(), {"sessions": []})
    return data.get("sessions") if isinstance(data, dict) else []


def _save_sessions(sessions):
    _write_json(_sessions_path(), {"sessions": sessions})


def signup(name, email, password):
    clean_name = str(name or "").strip()
    clean_email = str(email or "").strip().lower()
    clean_password = str(password or "")
    if len(clean_name) < 2:
        raise ValueError("Name is required.")
    if "@" not in clean_email or len(clean_email) < 5:
        raise ValueError("A valid email is required.")
    if len(clean_password) < 6:
        raise ValueError("Password must be at least 6 characters.")
    with _LOCK:
        users = load_users()
        if any(item.get("email") == clean_email for item in users):
            raise ValueError("An account with this email already exists.")
        salt, digest = _hash_password(clean_password)
        user = {
            "id": "usr_" + secrets.token_hex(6),
            "name": clean_name[:80],
            "email": clean_email,
            "role": "admin" if not users else "user",
            "salt": salt,
            "passwordHash": digest,
            "createdAt": _now(),
        }
        users.append(user)
        _save_users(users)
        token = _issue_session(user["id"])
    return _public_user(user), token


def login(email, password):
    clean_email = str(email or "").strip().lower()
    clean_password = str(password or "")
    users = load_users()
    found = next((item for item in users if item.get("email") == clean_email), None)
    if not found:
        raise ValueError("Email or password is wrong.")
    salt, digest = _hash_password(clean_password, found.get("salt"))
    if not hmac.compare_digest(digest, found.get("passwordHash") or ""):
        raise ValueError("Email or password is wrong.")
    with _LOCK:
        token = _issue_session(found["id"])
    return _public_user(found), token


def _issue_session(user_id):
    token = secrets.token_urlsafe(32)
    sessions = [item for item in load_sessions() if item.get("expiresAt", "") >= _now()]
    sessions.append({
        "tokenHash": _token_hash(token),
        "userId": user_id,
        "createdAt": _now(),
        "expiresAt": (datetime.now() + timedelta(days=SESSION_DAYS)).strftime("%Y-%m-%d %H:%M:%S"),
    })
    _save_sessions(sessions[-200:])
    return token


def logout(token):
    if not token:
        return
    digest = _token_hash(token)
    with _LOCK:
        sessions = [item for item in load_sessions() if item.get("tokenHash") != digest]
        _save_sessions(sessions)


def user_from_token(token):
    if not token:
        return None
    digest = _token_hash(str(token))
    now = _now()
    session = next((item for item in load_sessions() if item.get("tokenHash") == digest and item.get("expiresAt", "") >= now), None)
    if not session:
        return None
    found = next((item for item in load_users() if item.get("id") == session.get("userId")), None)
    return _public_user(found) if found else None


def current_user():
    return getattr(g, "portal_user", None)


def record_audit(user, module, action, detail, status):
    actor = user or {}
    entry = {
        "id": "aud_" + secrets.token_hex(6),
        "at": _now(),
        "userId": actor.get("id") or "",
        "user": actor.get("name") or actor.get("email") or "Unknown",
        "email": actor.get("email") or "",
        "role": actor.get("role") or "",
        "module": module or "Gateway",
        "action": action or "Activity",
        "detail": str(detail or "")[:240],
        "status": int(status or 0),
    }
    try:
        with _LOCK:
            with open(_audit_path(), "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
    except OSError as error:
        print("[portal_auth] audit write failed:", error)


def list_audit(actor, module="", role="", user_query="", limit=1000):
    rows = []
    path = _audit_path()
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.readlines()[-limit:]
        except OSError:
            lines = []
        for line in lines:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    if actor and actor.get("role") != "admin":
        rows = [item for item in rows if item.get("userId") == actor.get("id")]
    if module and module != "all":
        rows = [item for item in rows if item.get("module") == module]
    if role and role != "all":
        rows = [item for item in rows if item.get("role") == role]
    needle = str(user_query or "").strip().lower()
    if needle:
        rows = [item for item in rows if needle in " ".join([
            item.get("user") or "",
            item.get("email") or "",
            item.get("module") or "",
            item.get("action") or "",
            item.get("detail") or "",
        ]).lower()]
    rows.reverse()
    return rows


def module_for(path):
    if path.startswith("/api/auth"):
        return "Auth"
    if path.startswith("/api/persons"):
        return "People"
    if path.startswith("/api/records"):
        return "Attendance"
    if path.startswith("/api/devices") or path.startswith("/api/door") or path.startswith("/api/logs"):
        return "Devices"
    if path.startswith("/api/commands"):
        return "Communication"
    if path.startswith("/api/access"):
        return "Access"
    if path.startswith("/api/webhooks") or path.startswith("/api/settings"):
        return "Settings"
    if path.startswith("/api/audit"):
        return "Audit"
    if path.startswith("/api/dashboard") or path.startswith("/api/health"):
        return "Dashboard"
    return "Gateway"


def action_for(method, path):
    exact = {
        ("POST", "/api/auth/login"): "Logged in",
        ("POST", "/api/auth/signup"): "Signed up",
        ("POST", "/api/auth/logout"): "Logged out",
        ("POST", "/api/persons"): "Saved a person",
        ("POST", "/api/persons/delete"): "Deleted a person",
        ("POST", "/api/persons/push"): "Pushed a person to a device",
        ("POST", "/api/devices"): "Added a device",
        ("POST", "/api/devices/license"): "Saved a device license",
        ("POST", "/api/devices/name"): "Renamed a device",
        ("POST", "/api/devices/settings"): "Saved device settings",
        ("POST", "/api/devices/time"): "Synced device time",
        ("POST", "/api/devices/reboot"): "Rebooted a device",
        ("POST", "/api/devices/info"): "Requested device info",
        ("POST", "/api/door/open"): "Opened a door",
        ("POST", "/api/logs/pull"): "Pulled device logs",
        ("POST", "/api/webhooks"): "Created a webhook",
        ("PUT", "/api/webhooks/mode"): "Changed attendance mode",
        ("POST", "/api/commands"): "Queued a device command",
        ("POST", "/api/settings/webhook"): "Saved webhook settings",
        ("POST", "/api/audit"): "Opened a page",
    }
    if (method, path) in exact:
        return exact[(method, path)]
    if method == "PUT" and path.startswith("/api/webhooks/"):
        return "Updated a webhook"
    if method == "DELETE" and path.startswith("/api/webhooks/"):
        return "Deleted a webhook"
    if method == "POST" and path.endswith("/test"):
        return "Sent a webhook test"
    return f"{method} {path}"


def _safe_detail(status):
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}
    bits = []
    for key in ("email", "name", "deviceSn", "enrollId", "mode", "module", "action"):
        value = data.get(key)
        if value not in (None, ""):
            bits.append(f"{key} {value}")
    bits.append(f"HTTP {status}")
    return " · ".join(str(part) for part in bits)[:240]


def note_request(status):
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.path == "/api/audit":
        return
    actor = current_user()
    if actor is None and request.path == "/api/auth/login":
        data = request.get_json(silent=True) or {}
        email = str((data or {}).get("email") or "").strip().lower()
        actor = {"id": "", "name": email or "Unknown", "email": email, "role": ""}
    record_audit(actor, module_for(request.path), action_for(request.method, request.path), _safe_detail(status), status)
