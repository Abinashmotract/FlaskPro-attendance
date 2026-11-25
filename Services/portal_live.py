"""Browser clients listening for punches and device presence."""
import json

_clients = set()


def register(sock):
    _clients.add(sock)


def unregister(sock):
    _clients.discard(sock)


def publish(event):
    raw = json.dumps(event, default=str)
    dead = []
    for sock in list(_clients):
        try:
            sock.send(raw)
        except Exception:
            dead.append(sock)
    for sock in dead:
        _clients.discard(sock)


def _socket_of(status):
    if isinstance(status, dict):
        return status.get("websocket")
    return getattr(status, "websocket", None)


def _mark_offline(serial):
    publish({"type": "device", "serial": serial, "online": False})
    try:
        from Models.Device import get_device_by_serial_num, update_status_by_primary_key
        device = get_device_by_serial_num(serial)
        if device is not None:
            update_status_by_primary_key(device.id, 0)
    except Exception:
        pass
    try:
        from Services.erp_bridge import forward_gateway_event
        forward_gateway_event("device_offline", serial)
    except Exception:
        pass


def prune_offline_devices():
    """Remove sockets the terminal has already dropped."""
    from web_socket.WebSocketPool import ws_device
    removed = []
    for serial, status in list(ws_device.items()):
        sock = _socket_of(status)
        if sock is None or getattr(sock, "connected", True) is False:
            ws_device.pop(serial, None)
            removed.append(serial)
    for serial in removed:
        _mark_offline(serial)
    return removed


def drop_device_socket(sock):
    from web_socket.WebSocketPool import ws_device
    found = None
    for serial, status in list(ws_device.items()):
        if _socket_of(status) is sock:
            del ws_device[serial]
            found = serial
    if found:
        _mark_offline(found)
    return found
