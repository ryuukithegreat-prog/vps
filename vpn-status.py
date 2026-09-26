#!/usr/bin/env python3
import csv
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else ""
    except OSError:
        return ""


def parse_wg_output(output, now=None):
    current_time = time.time() if now is None else now
    active_clients = 0
    total_clients = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue

        total_clients += 1
        try:
            last_handshake = int(parts[5])
        except ValueError:
            continue

        if 0 <= current_time - last_handshake <= 180:
            active_clients += 1

    return {"active_clients": active_clients, "total_clients": total_clients}


def parse_wg():
    return parse_wg_output(run(["wg", "show", "all", "dump"]))


def parse_openvpn_status(text):
    active_clients = 0
    legacy_client_section = False
    for row in csv.reader(text.splitlines()):
        if not row:
            continue
        if row[0] == "CLIENT_LIST":
            if len(row) > 1 and row[1] != "Common Name":
                active_clients += 1
        elif row[0] == "Common Name" and len(row) > 1 and row[1] == "Real Address":
            legacy_client_section = True
        elif row[0] == "ROUTING TABLE":
            legacy_client_section = False
        elif legacy_client_section:
            active_clients += 1
    return active_clients


def parse_ipsec():
    output = run(["ipsec", "statusall"])
    count = sum(1 for line in output.splitlines() if "ESTABLISHED" in line)
    return {"active_tunnels": count}


def parse_openvpn():
    status_file = Path("/var/log/openvpn-status.log")
    if not status_file.exists():
        return {"active_clients": 0}
    try:
        return {"active_clients": parse_openvpn_status(status_file.read_text(errors="replace"))}
    except OSError:
        return {"active_clients": 0}


def parse_ufw():
    status = run(["ufw", "status"])
    return {"enabled": status.startswith("Status: active")}


def resolve_service_units():
    output = run(["systemctl", "list-unit-files", "--type=service", "--no-legend"])
    available = {line.split()[0] for line in output.splitlines() if line.split()}
    options = {
        "nginx": ("nginx.service",),
        "wireguard": ("wg-quick@wg0.service", "wg-quick@.service"),
        "openvpn": ("openvpn.service", "openvpn-server@.service"),
        "ipsec": ("strongswan.service", "strongswan-starter.service"),
    }
    fallback = {
        "nginx": "nginx.service",
        "wireguard": "wg-quick@wg0.service",
        "openvpn": "openvpn-server@server.service",
        "ipsec": "strongswan-starter.service",
    }
    resolved = {}
    for name, candidates in options.items():
        unit = next((candidate for candidate in candidates if candidate in available), None)
        if unit and unit.endswith("@.service"):
            instance = "wg0" if name == "wireguard" else "server"
            unit = unit.replace("@.service", f"@{instance}.service")
        resolved[name] = unit or fallback[name]
    return resolved


def parse_services():
    units = resolve_service_units()
    result = {}
    for name, unit in units.items():
        status = run(["systemctl", "is-active", unit])
        result[name] = status or "inactive"
    return result, {name: unit.removesuffix(".service") for name, unit in units.items()}


def main():
    services, service_units = parse_services()
    payload = {
        "domain": os.environ.get("DOMAIN", "vpn.example.com"),
        "ssh_banner": os.environ.get("SSH_BANNER_MODE", "1"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "protocols": {
            "wireguard": parse_wg(),
            "ipsec": parse_ipsec(),
            "openvpn": parse_openvpn(),
            "services": services,
            "service_units": service_units,
            "firewall": parse_ufw(),
        },
        "banned_users": [],
        "knockouts": [],
        "summary": {
            "active_users": 0,
            "banned_count": 0,
            "online_services": 0,
        },
    }
    services = payload["protocols"]["services"]
    payload["summary"]["online_services"] = sum(1 for status in services.values() if status == "active")
    payload["summary"]["active_users"] = (
        payload["protocols"]["wireguard"]["active_clients"]
        + payload["protocols"]["openvpn"]["active_clients"]
        + payload["protocols"]["ipsec"]["active_tunnels"]
    )
    payload["summary"]["banned_count"] = len(payload["banned_users"])
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
