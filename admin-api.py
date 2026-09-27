#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import logging
import os
import re
import secrets
import uuid
import sqlite3
import subprocess
import threading
import tempfile
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


DB_PATH = Path(os.environ.get("VPN_ADMIN_DB", "/var/lib/vpnfront/admin.sqlite3"))
STATUS_PATH = Path(os.environ.get("VPN_STATUS_PATH", "/var/lib/vpnfront/status.json"))
SESSION_COOKIE = "vpn_session"
SESSION_TTL = 8 * 60 * 60
CLIENT_SESSION_COOKIE = "vpn_client_session"
CLIENT_SESSION_TTL = 12 * 60 * 60
PBKDF2_ITERATIONS = 310_000
BOOTSTRAP_PASSWORD_MIN_LENGTH = 10
PASSWORD_MIN_LENGTH = 14
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MAX_BODY_SIZE = 8192
MAX_ADMINS = 20
CLIENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_CONFIG_PATH = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"))
ADBLOCK_CONFIG_PATH = Path(os.environ.get("ADBLOCK_CONFIG_PATH", "/etc/dnsmasq.d/vpnfront-adblock.conf"))
ADBLOCK_HOSTS_PATH = Path(os.environ.get("ADBLOCK_HOSTS_PATH", "/var/lib/vpnfront/ads.hosts"))
ADBLOCK_STATE_PATH = Path(os.environ.get("ADBLOCK_STATE_PATH", "/var/lib/vpnfront/adblock.json"))
MAINTENANCE_STATE_PATH = Path(os.environ.get("MAINTENANCE_STATE_PATH", "/var/lib/vpnfront/maintenance.json"))
MAINTENANCE_FIREWALL_COMMAND = os.environ.get(
    "MAINTENANCE_FIREWALL_COMMAND", "/usr/local/sbin/vpn-maintenance-firewall"
)
ADBLOCK_SOURCE_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
ADBLOCK_LEVELS = {
    "light": {
        "label": "Light",
        "url": ADBLOCK_SOURCE_URL,
    },
    "balanced": {
        "label": "Balanced",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts",
    },
    "strict": {
        "label": "Strict",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    },
}
BLOCKED_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
MAX_BLOCKED_DOMAINS = 500
WG_CLIENT_NETWORK = ipaddress.ip_network("10.42.0.0/24")
WG_GATEWAY_ADDRESS = ipaddress.ip_address("10.42.0.1")
WG_ROUTE_MODES = {"full": "0.0.0.0/0", "split": str(WG_CLIENT_NETWORK)}
WG_DEFAULT_PORT = 51820
WG_HANDSHAKE_ACTIVE_SECONDS = 180
CLIENT_DURATION_OPTIONS = {0, 1, 7, 30, 90}
MAX_CLIENT_DURATION_SECONDS = 365 * 24 * 60 * 60
client_operations_lock = threading.RLock()
SERVICE_UNITS = {
    "nginx": ("nginx.service",),
    "wireguard": ("wg-quick@wg0.service", "wg-quick@.service"),
    "openvpn": ("openvpn.service", "openvpn-server@.service"),
    "ipsec": ("strongswan-starter.service", "strongswan.service"),
}
DEFAULT_SERVICE_UNITS = {
    "nginx": "nginx.service",
    "wireguard": "wg-quick@wg0.service",
    "openvpn": "openvpn-server@server.service",
    "ipsec": "strongswan-starter.service",
}
LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_SECONDS = 900
login_attempts = {}
login_attempts_lock = threading.Lock()
logger = logging.getLogger("vpn-admin-api")


class ExpiredClientError(ValueError):
    pass


@contextmanager
def database():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database():
    DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DB_PATH.parent, 0o700)
    with database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vpn_clients (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL UNIQUE,
                private_key TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                password_salt BLOB,
                password_hash BLOB,
                must_change_password INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS client_sessions (
                token_hash BLOB PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES vpn_clients(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            """
        )
        client_columns = {row["name"] for row in connection.execute("PRAGMA table_info(vpn_clients)")}
        if "password_salt" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN password_salt BLOB")
        if "password_hash" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN password_hash BLOB")
        if "must_change_password" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        if "protocol" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN protocol TEXT NOT NULL DEFAULT 'wireguard'")
        if "metadata" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN metadata TEXT")
        if "route_mode" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN route_mode TEXT NOT NULL DEFAULT 'full'")
    if DB_PATH.exists():
        os.chmod(DB_PATH, 0o600)


def validate_username(username):
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3-32 letters, digits, dots, underscores, or hyphens.")


def validate_password(password, minimum=PASSWORD_MIN_LENGTH):
    if not isinstance(password, str) or len(password) < minimum or len(password) > 256:
        raise ValueError(f"Password must be between {minimum} and 256 characters.")


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def add_admin(username, password, must_change_password=False, bootstrap=False):
    validate_username(username)
    validate_password(password, BOOTSTRAP_PASSWORD_MIN_LENGTH if bootstrap else PASSWORD_MIN_LENGTH)
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        count = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count >= MAX_ADMINS:
            raise ValueError("The maximum number of admin accounts has been reached.")
        try:
            connection.execute(
                "INSERT INTO admins(username, salt, password_hash, created_at, must_change_password) VALUES (?, ?, ?, ?, ?)",
                (username, salt, digest, int(time.time()), int(must_change_password)),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That username already exists.") from exc


def bootstrap_admin(username, password):
    validate_username(username)
    validate_password(password, BOOTSTRAP_PASSWORD_MIN_LENGTH)
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    with database() as connection:
        count = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count:
            return False
        connection.execute(
            "INSERT INTO admins(username, salt, password_hash, created_at, must_change_password) VALUES (?, ?, ?, ?, 1)",
            (username, salt, digest, int(time.time())),
        )
    return True


def verify_password(username, password):
    with database() as connection:
        row = connection.execute(
            "SELECT salt, password_hash, must_change_password FROM admins WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        password_digest(password, b"\0" * 16)
        return None
    if not hmac.compare_digest(password_digest(password, row["salt"]), row["password_hash"]):
        return None
    return {"username": username, "must_change_password": bool(row["must_change_password"])}


def verify_client_password(username, password):
    with database() as connection:
        row = connection.execute(
            "SELECT id, password_salt, password_hash, must_change_password FROM vpn_clients WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or row["password_salt"] is None or row["password_hash"] is None:
        password_digest(password, b"\0" * 16)
        return None
    if not hmac.compare_digest(password_digest(password, row["password_salt"]), row["password_hash"]):
        return None
    return {"id": row["id"], "username": username, "must_change_password": bool(row["must_change_password"])}


def new_session(username):
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).digest()
    with database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        connection.execute(
            "INSERT INTO sessions(token_hash, username, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, username, csrf_token, int(time.time()) + SESSION_TTL),
        )
    return token, csrf_token


def new_client_session(client_id):
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).digest()
    with database() as connection:
        connection.execute("DELETE FROM client_sessions WHERE expires_at < ?", (int(time.time()),))
        connection.execute(
            "INSERT INTO client_sessions(token_hash, client_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, client_id, csrf_token, int(time.time()) + CLIENT_SESSION_TTL),
        )
    return token, csrf_token


def reset_client_portal_password(client_id):
    with database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            raise ValueError("VPN account not found.")
        temporary_password = secrets.token_urlsafe(18)
        salt = secrets.token_bytes(16)
        digest = password_digest(temporary_password, salt)
        connection.execute(
            "UPDATE vpn_clients SET password_salt = ?, password_hash = ?, must_change_password = 1 WHERE id = ?",
            (salt, digest, client_id),
        )
        connection.execute("DELETE FROM client_sessions WHERE client_id = ?", (client_id,))
    return row["username"], temporary_password


def delete_user_sessions(username):
    with database() as connection:
        connection.execute("DELETE FROM sessions WHERE username = ?", (username,))


def list_admins():
    with database() as connection:
        rows = connection.execute("SELECT username, created_at FROM admins ORDER BY username COLLATE NOCASE").fetchall()
    return [{"username": row["username"], "created_at": row["created_at"]} for row in rows]


def delete_admin(username, current_username):
    if username == current_username:
        raise ValueError("You cannot remove the account you are using.")
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        count = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count <= 1:
            raise ValueError("The last admin account cannot be removed.")
        cursor = connection.execute("DELETE FROM admins WHERE username = ?", (username,))
        if cursor.rowcount == 0:
            raise ValueError("Admin account not found.")


def validate_client_name(username):
    if not isinstance(username, str):
        raise ValueError("Username must be a string.")
    username = username.strip()
    if not (1 <= len(username) <= 48):
        raise ValueError("Username must be 1-48 characters.")
    # Allow letters, digits, dashes, underscores, dots, @, and most
    # common identifier punctuation. Block only path separators and shell metachars.
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9._@+-]+", username):
        raise ValueError("Username may only contain letters, digits, ., _, -, @, +.")
    return username


def parse_client_duration(payload):
    duration_seconds = payload.get("durationSeconds", payload.get("durationHours"))
    legacy_days = payload.get("durationDays")
    if duration_seconds is None and legacy_days is None:
        return 30 * 24 * 60 * 60

    value = legacy_days if duration_seconds is None else duration_seconds
    if isinstance(value, bool) or not (
        isinstance(value, int)
        or isinstance(value, str) and re.fullmatch(r"\d+", value.strip())
    ):
        raise ValueError("Duration must be a non-negative whole number.")
    value = int(value)
    seconds = value * 86400 if duration_seconds is None else value
    if seconds < 0:
        raise ValueError("Duration must be a non-negative whole number.")
    if seconds > MAX_CLIENT_DURATION_SECONDS:
        raise ValueError("Duration cannot exceed 365 days.")
    return seconds


def wireguard_command(arguments, input_text=None):
    try:
        result = subprocess.run(
            ["wg", *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("WireGuard is unavailable. Check that wg0 is running.") from exc
    if result.returncode != 0:
        raise RuntimeError("WireGuard operation failed. Check that wg0 is running.")
    return result.stdout.strip()


def _parse_allowed_networks(value):
    networks = []
    for address in value.split(","):
        try:
            networks.append(ipaddress.ip_network(address.strip(), strict=False))
        except ValueError:
            continue
    return networks


def _configured_peer_networks(config_text):
    networks = []
    in_peer = False
    for line in config_text.splitlines():
        section = re.fullmatch(r"\s*\[([^]]+)\]\s*", line)
        if section:
            in_peer = section.group(1).lower() == "peer"
        elif in_peer:
            allowed = re.match(r"\s*AllowedIPs\s*=\s*(.+)", line, re.IGNORECASE)
            if allowed:
                networks.extend(_parse_allowed_networks(allowed.group(1)))
    return networks


def _live_peer_networks(dump):
    networks = []
    for line in dump.splitlines():
        columns = line.split("\t")
        if len(columns) >= 8:
            networks.extend(_parse_allowed_networks(columns[3]))
    return networks


def _allocate_client_address(connection, config_text, dump):
    allocated = set()
    for row in connection.execute("SELECT address FROM vpn_clients"):
        try:
            allocated.add(ipaddress.ip_address(row[0]))
        except (ValueError, TypeError):
            continue
    networks = _configured_peer_networks(config_text) + _live_peer_networks(dump)
    for address in WG_CLIENT_NETWORK.hosts():
        if address == WG_GATEWAY_ADDRESS or address in allocated:
            continue
        if any(address in network for network in networks):
            continue
        return address
    raise ValueError("The WireGuard address pool is full.")


def _write_wireguard_config(config_text):
    WG_CONFIG_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".wg0-", dir=WG_CONFIG_PATH.parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(config_text)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, WG_CONFIG_PATH)
        os.chmod(WG_CONFIG_PATH, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def _wireguard_endpoint():
    endpoint = os.environ.get("DOMAIN", "vpn.example.com").strip()
    try:
        address = ipaddress.ip_address(endpoint)
        endpoint = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", endpoint) or endpoint.startswith(".") or endpoint.endswith("."):
            raise RuntimeError("The configured VPN endpoint is invalid.")
    try:
        port = int(os.environ.get("WG_PORT", str(WG_DEFAULT_PORT)))
    except ValueError as exc:
        raise RuntimeError("The configured WireGuard port is invalid.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("The configured WireGuard port is invalid.")
    return f"{endpoint}:{port}"


def read_adblock_state():
    try:
        state = json.loads(ADBLOCK_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    level = state.get("level", "balanced")
    if level not in ADBLOCK_LEVELS:
        level = "balanced"
    blocked_domains = state.get("blocked_domains", [])
    if not isinstance(blocked_domains, list):
        blocked_domains = []
    blocked_domains = [
        domain.lower()
        for domain in blocked_domains
        if isinstance(domain, str) and BLOCKED_DOMAIN_PATTERN.fullmatch(domain)
    ][:MAX_BLOCKED_DOMAINS]
    return {
        "enabled": state.get("enabled") is True,
        "hostCount": max(0, int(state.get("host_count", 0) or 0)),
        "updatedAt": state.get("updated_at"),
        "lastError": state.get("last_error"),
        "level": level,
        "blockedDomains": blocked_domains,
        "source": f"StevenBlack {ADBLOCK_LEVELS[level]['label']} hosts",
        "sourceUrl": ADBLOCK_LEVELS[level]["url"],
    }


def validate_blocked_domains(domains):
    if not isinstance(domains, list) or len(domains) > MAX_BLOCKED_DOMAINS:
        raise ValueError(f"Provide up to {MAX_BLOCKED_DOMAINS} blocked domains.")
    normalized = []
    for domain in domains:
        if not isinstance(domain, str):
            raise ValueError("Each blocked website must be a domain name.")
        domain = domain.strip().lower()
        if not BLOCKED_DOMAIN_PATTERN.fullmatch(domain):
            raise ValueError(f"Invalid blocked domain: {domain or '(empty)'}")
        if domain not in normalized:
            normalized.append(domain)
    return normalized


def read_maintenance_state():
    try:
        state = json.loads(MAINTENANCE_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    message = state.get("message", "")
    if not isinstance(message, str):
        message = ""
    return {
        "enabled": state.get("enabled") is True,
        "message": message[:500],
        "blockInternet": state.get("block_internet") is True,
    }


def set_vpn_forwarding_block(enabled):
    if not isinstance(enabled, bool):
        raise ValueError("Internet pause must be enabled or disabled.")
    result = subprocess.run(
        [MAINTENANCE_FIREWALL_COMMAND, "enable" if enabled else "disable"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Could not update the VPN maintenance firewall rules.")


def set_maintenance_state(enabled, message, block_internet=False):
    if not isinstance(enabled, bool):
        raise ValueError("Maintenance notice must be enabled or disabled.")
    if not isinstance(block_internet, bool):
        raise ValueError("Internet pause must be enabled or disabled.")
    if block_internet and not enabled:
        raise ValueError("Enable the client maintenance notice when pausing VPN internet access.")
    if not isinstance(message, str) or len(message) > 500:
        raise ValueError("Maintenance notice must be 500 characters or fewer.")
    previous = read_maintenance_state()
    state = {"enabled": enabled, "message": message.strip(), "blockInternet": block_internet}
    persisted = {"enabled": enabled, "message": message.strip(), "block_internet": block_internet}
    _atomic_private_write(MAINTENANCE_STATE_PATH, json.dumps(persisted, separators=(",", ":")) + "\n")
    try:
        set_vpn_forwarding_block(block_internet)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        _atomic_private_write(
            MAINTENANCE_STATE_PATH,
            json.dumps(
                {
                    "enabled": previous["enabled"],
                    "message": previous["message"],
                    "block_internet": previous["blockInternet"],
                },
                separators=(",", ":"),
            )
            + "\n",
        )
        try:
            set_vpn_forwarding_block(previous["blockInternet"])
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            logger.exception("Failed to restore VPN forwarding after maintenance update failure")
        raise
    return state


def _atomic_private_write(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def _write_adblock_state(
    enabled, host_count=0, updated_at=None, last_error=None, level="balanced", blocked_domains=()
):
    state = {
        "enabled": bool(enabled),
        "host_count": max(0, int(host_count)),
        "updated_at": updated_at,
        "last_error": last_error,
        "level": level,
        "blocked_domains": list(blocked_domains),
    }
    _atomic_private_write(ADBLOCK_STATE_PATH, json.dumps(state, separators=(",", ":")) + "\n")
    return read_adblock_state()


def set_adblock_enabled(enabled, level=None, blocked_domains=None):
    if not isinstance(enabled, bool):
        raise ValueError("Ad blocking must be enabled or disabled.")
    current_state = read_adblock_state()
    level = current_state["level"] if level is None else level
    if not isinstance(level, str) or level not in ADBLOCK_LEVELS:
        raise ValueError("Choose a valid ad-blocking level.")
    if blocked_domains is None:
        blocked_domains = current_state["blockedDomains"]
    blocked_domains = validate_blocked_domains(blocked_domains)
    previous_config = ADBLOCK_CONFIG_PATH.read_bytes() if ADBLOCK_CONFIG_PATH.exists() else None
    previous_state = ADBLOCK_STATE_PATH.read_bytes() if ADBLOCK_STATE_PATH.exists() else None
    if (
        current_state["enabled"] == enabled
        and current_state["level"] == level
        and current_state["blockedDomains"] == blocked_domains
    ):
        return current_state
    try:
        if enabled:
            _atomic_private_write(ADBLOCK_CONFIG_PATH, f"addn-hosts={ADBLOCK_HOSTS_PATH}\n")
        else:
            ADBLOCK_CONFIG_PATH.unlink(missing_ok=True)
        _write_adblock_state(
            enabled,
            host_count=current_state["hostCount"],
            updated_at=current_state["updatedAt"],
            last_error=None,
            level=level,
            blocked_domains=blocked_domains,
        )
        validation = subprocess.run(
            ["dnsmasq", "--test"], capture_output=True, text=True, timeout=10, check=False
        )
        if validation.returncode != 0:
            raise RuntimeError("dnsmasq rejected the ad-block configuration.")
        reload_result = subprocess.run(
            ["systemctl", "reload", "dnsmasq"], capture_output=True, text=True, timeout=15, check=False
        )
        if reload_result.returncode != 0:
            raise RuntimeError("The VPN DNS resolver could not reload its configuration.")
        if enabled:
            update_result = subprocess.run(
                ["systemctl", "start", "--no-block", "vpn-adblock-update.service"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if update_result.returncode != 0:
                raise RuntimeError("The ad-block list updater could not be started.")
        return read_adblock_state()
    except (OSError, subprocess.TimeoutExpired, RuntimeError):
        if previous_config is None:
            ADBLOCK_CONFIG_PATH.unlink(missing_ok=True)
        else:
            _atomic_private_write(ADBLOCK_CONFIG_PATH, previous_config.decode("utf-8"))
        if previous_state is None:
            ADBLOCK_STATE_PATH.unlink(missing_ok=True)
        else:
            _atomic_private_write(ADBLOCK_STATE_PATH, previous_state.decode("utf-8"))
        try:
            subprocess.run(["systemctl", "reload", "dnsmasq"], capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            logger.exception("Failed to roll back DNS resolver configuration")
        raise


def validate_wireguard_route_mode(route_mode):
    if not isinstance(route_mode, str) or route_mode not in WG_ROUTE_MODES:
        raise ValueError("WireGuard route mode must be full or split.")
    return route_mode


def create_wireguard_client(username, duration_days, route_mode="full"):
    username = validate_client_name(username)
    route_mode = validate_wireguard_route_mode(route_mode)
    if duration_days is not None and (isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days < 0):
        raise ValueError("Invalid duration.")

    with client_operations_lock, database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM vpn_clients WHERE username = ?", (username,)).fetchone():
            raise ValueError("That VPN account name already exists.")
        try:
            config_text = WG_CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("WireGuard configuration is unavailable.") from exc
        live_dump = wireguard_command(["show", WG_INTERFACE, "dump"])
        server_public_key = wireguard_command(["show", WG_INTERFACE, "public-key"])
        endpoint = _wireguard_endpoint()
        address = _allocate_client_address(connection, config_text, live_dump)
        private_key = wireguard_command(["genkey"])
        public_key = wireguard_command(["pubkey"], input_text=f"{private_key}\n")
        if not private_key or not public_key:
            raise RuntimeError("WireGuard did not generate a client key pair.")

        now = int(time.time())
        expires_at = now + duration_days if duration_days else None
        client_id = secrets.token_hex(16)
        temporary_password = secrets.token_urlsafe(18)
        password_salt = secrets.token_bytes(16)
        password_hash = password_digest(temporary_password, password_salt)
        peer_config = f"[Peer]\nPublicKey = {public_key}\nAllowedIPs = {address}/32\n"
        updated_config = f"{config_text.rstrip()}\n\n{peer_config}"
        _write_wireguard_config(updated_config)
        try:
            wireguard_command(["set", WG_INTERFACE, "peer", public_key, "allowed-ips", f"{address}/32"])
        except RuntimeError:
            _write_wireguard_config(config_text)
            raise
        connection.execute(
            "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, password_salt, password_hash, must_change_password, route_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (client_id, username, public_key, private_key, str(address), now, expires_at, password_salt, password_hash, route_mode),
        )
        client_config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}/32\n"
            f"DNS = {WG_GATEWAY_ADDRESS}\n\n"
            "[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {endpoint}\n"
            f"AllowedIPs = {WG_ROUTE_MODES[route_mode]}\n"
            "PersistentKeepalive = 25\n"
        )
    return {"id": client_id, "username": username, "protocol": "wireguard", "address": str(address), "createdAt": now, "expiresAt": expires_at, "temporaryPassword": temporary_password, "routeMode": route_mode}, client_config



XRAY_CONFIG_PATH = Path("/usr/local/etc/xray/config.json")
XRAY_XHTTP_PATH = "/saeka-vless-xh"

def create_xray_client(username, duration_days):
    username = validate_client_name(username)
    if duration_days is not None and (isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days < 0):
        raise ValueError("Invalid duration.")
    with client_operations_lock, database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM vpn_clients WHERE username = ?", (username,)).fetchone():
            raise ValueError("That VPN account name already exists.")
        try:
            cfg = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("Xray configuration is unavailable.") from exc
        client_uuid = str(uuid.uuid4())
        added = 0
        for ib in cfg.get("inbounds", []):
            proto = ib.get("protocol")
            if proto in ("vless", "vmess"):
                ib.setdefault("settings", {}).setdefault("clients", []).append({"id": client_uuid, "email": username})
                added += 1
            elif proto == "trojan":
                ib.setdefault("settings", {}).setdefault("clients", []).append({"password": client_uuid, "email": username})
                added += 1
        if added == 0:
            raise RuntimeError("No Xray inbounds available to accept client.")
        tmp = XRAY_CONFIG_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        os.replace(tmp, XRAY_CONFIG_PATH)
        now = int(time.time())
        expires_at = now + duration_days if duration_days else None
        client_id = secrets.token_hex(16)
        temp_password = secrets.token_urlsafe(18)
        salt = secrets.token_bytes(16)
        pwh = password_digest(temp_password, salt)
        metadata = json.dumps({"uuid": client_uuid})
        connection.execute(
            "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, password_salt, password_hash, must_change_password, protocol, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'xray', ?)",
            (client_id, username, "xray:" + client_id, "xray:" + client_id, "xray:" + client_id, now, expires_at, salt, pwh, metadata),
        )
    try:
        subprocess.run(["systemctl", "reload", "xray"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    host = _vpn_host()
    share = f"vless://{client_uuid}@{_host_port(host, 443)}?encryption=none&security=tls&sni={host}&type=splithttp&host={host}&path=%2F{XRAY_XHTTP_PATH.lstrip('/')}&mode=auto#{username}"
    return {"id": client_id, "username": username, "protocol": "xray", "createdAt": now, "expiresAt": expires_at, "temporaryPassword": temp_password}, share


def create_ssh_client(username, duration_days):
    username = validate_client_name(username)
    if duration_days is not None and (isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days < 0):
        raise ValueError("Invalid duration.")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]{0,31}", username):
        raise ValueError("SSH usernames: letters/digits/underscore/hyphen, start with letter.")
    with client_operations_lock, database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM vpn_clients WHERE username = ?", (username,)).fetchone():
            raise ValueError("That VPN account name already exists.")
        temp_password = secrets.token_urlsafe(18)
        cmd = ["useradd", "-M", "-s", "/usr/sbin/nologin"]
        cmd.append(username)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        if r.returncode != 0:
            raise RuntimeError("useradd failed: " + r.stderr.strip())
        r2 = subprocess.run(["chpasswd"], input=username + ":" + temp_password + "\n", capture_output=True, text=True, timeout=10, check=False)
        if r2.returncode != 0:
            subprocess.run(["userdel", username], capture_output=True, timeout=10, check=False)
            raise RuntimeError("chpasswd failed.")
        subprocess.run(["chage", "-d", "0", username], capture_output=True, timeout=10, check=False)
        now = int(time.time())
        expires_at = now + duration_days if duration_days else None
        client_id = secrets.token_hex(16)
        salt = secrets.token_bytes(16)
        pwh = password_digest(temp_password, salt)
        metadata = json.dumps({"system_user": username})
        connection.execute(
            "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, password_salt, password_hash, must_change_password, protocol, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'ssh', ?)",
            (client_id, username, "ssh:" + client_id, "ssh:" + client_id, "ssh:" + client_id, now, expires_at, salt, pwh, metadata),
        )
    host = _vpn_host()
    info = "SSH Tunnel\n==========\nHost: " + host + "\nPort: 22\nUser: " + username + "\nPassword: " + temp_password + "\n\nssh " + username + "@" + host
    return {"id": client_id, "username": username, "protocol": "ssh", "createdAt": now, "expiresAt": expires_at, "temporaryPassword": temp_password}, info


def get_client_protocol(client_id):
    with database() as connection:
        row = connection.execute("SELECT protocol FROM vpn_clients WHERE id = ?", (client_id,)).fetchone()
    return row["protocol"] if row else "wireguard"


def get_xray_client_share(client_id):
    with database() as connection:
        row = connection.execute("SELECT username, metadata FROM vpn_clients WHERE id = ? AND protocol = 'xray'", (client_id,)).fetchone()
    if row is None:
        raise ValueError("Xray account not found.")
    try:
        meta = json.loads(row["metadata"] or "{}")
    except json.JSONDecodeError:
        meta = {}
    client_uuid = meta.get("uuid", "")
    host = _vpn_host()
    share = f"vless://{client_uuid}@{_host_port(host, 443)}?encryption=none&security=tls&sni={host}&type=xhttp&host={host}&path=%2F{XRAY_XHTTP_PATH.lstrip('/')}&mode=auto#{row['username']}"
    return row["username"], share


def get_ssh_client_info(client_id):
    with database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ? AND protocol = 'ssh'", (client_id,)).fetchone()
    if row is None:
        raise ValueError("SSH account not found.")
    host = _vpn_host()
    info = "SSH Tunnel\n==========\nHost: " + host + "\nPort: 22\nUser: " + row["username"] + "\n\nssh " + row["username"] + "@" + host
    return row["username"], info


def revoke_xray_client(client_id):
    with client_operations_lock, database() as connection:
        row = connection.execute("SELECT username, metadata FROM vpn_clients WHERE id = ? AND protocol = 'xray'", (client_id,)).fetchone()
        if row is None:
            raise ValueError("Xray account not found.")
        try:
            meta = json.loads(row["metadata"] or "{}")
        except json.JSONDecodeError:
            meta = {}
        client_uuid = meta.get("uuid")
        try:
            cfg = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("Xray configuration is unavailable.") from exc
        for ib in cfg.get("inbounds", []):
            protocol = ib.get("protocol")
            key = "password" if protocol == "trojan" else "id"
            if protocol in {"vless", "vmess", "trojan"}:
                clients = ib.get("settings", {}).get("clients", [])
                ib["settings"]["clients"] = [
                    client for client in clients if client.get(key) != client_uuid
                ]
        tmp = XRAY_CONFIG_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        os.replace(tmp, XRAY_CONFIG_PATH)
        connection.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))
    try:
        subprocess.run(["systemctl", "reload", "xray"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


def revoke_ssh_client(client_id):
    with client_operations_lock, database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ? AND protocol = 'ssh'", (client_id,)).fetchone()
        if row is None:
            raise ValueError("SSH account not found.")
        username = row["username"]
        subprocess.run(["pkill", "-KILL", "-u", username], capture_output=True, timeout=10, check=False)
        subprocess.run(["userdel", "-r", username], capture_output=True, timeout=15, check=False)
        connection.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))



EASYRSA_DIR = Path("/etc/openvpn/easy-rsa")
OPENVPN_CRL_PATH = Path("/etc/openvpn/server/crl.pem")
IPSEC_SECRETS = Path("/etc/ipsec.secrets")


def _vpn_host():
    try:
        host = urlsplit(f"//{_wireguard_endpoint()}").hostname
    except ValueError as exc:
        raise RuntimeError("The configured VPN endpoint is invalid.") from exc
    if not host:
        raise RuntimeError("The configured VPN endpoint is invalid.")
    return host


def _host_authority(host):
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host
    return f"[{address.compressed}]" if address.version == 6 else str(address)


def _host_port(host, port):
    return f"{_host_authority(host)}:{port}"


def create_openvpn_client(username, duration_days):
    username = validate_client_name(username)
    if duration_days is not None and (isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days < 0):
        raise ValueError("Invalid duration.")
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", username):
        raise ValueError("OpenVPN username: letters/digits/underscore/hyphen only.")
    with client_operations_lock, database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM vpn_clients WHERE username = ?", (username,)).fetchone():
            raise ValueError("That VPN account name already exists.")
        try:
            r = subprocess.run(["./easyrsa", "--batch", "build-client-full", username, "nopass"],
                               cwd=str(EASYRSA_DIR), capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("OpenVPN client certificate generation failed.") from exc
        if r.returncode != 0:
            raise RuntimeError("easy-rsa failed: " + (r.stderr.strip() or r.stdout.strip()))
        cert_path = EASYRSA_DIR / "pki" / "issued" / (username + ".crt")
        key_path = EASYRSA_DIR / "pki" / "private" / (username + ".key")
        if not cert_path.exists() or not key_path.exists():
            raise RuntimeError("Client certificate generation failed.")
        ca = (EASYRSA_DIR / "pki" / "ca.crt").read_text()
        cert = cert_path.read_text()
        key = key_path.read_text()
        ta = Path("/etc/openvpn/ta.key").read_text()
        ovpn = ("client\ndev tun\nproto udp\nremote " + _vpn_host() + " 1194\n"
                "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
                "remote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n"
                "key-direction 1\nverb 3\n<ca>\n" + ca + "</ca>\n<cert>\n" + cert +
                "</cert>\n<key>\n" + key + "</key>\n<tls-auth>\n" + ta + "</tls-auth>\n")
        now = int(time.time())
        expires_at = now + duration_days if duration_days else None
        client_id = secrets.token_hex(16)
        temp_pw = secrets.token_urlsafe(18)
        salt = secrets.token_bytes(16)
        pwh = password_digest(temp_pw, salt)
        meta = json.dumps({"cn": username})
        connection.execute(
            "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, password_salt, password_hash, must_change_password, protocol, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'openvpn', ?)",
            (client_id, username, "ovpn:" + client_id, "ovpn:" + client_id, "ovpn:" + client_id, now, expires_at, salt, pwh, meta))
    return {"id": client_id, "username": username, "protocol": "openvpn", "createdAt": now, "expiresAt": expires_at, "temporaryPassword": temp_pw}, ovpn


def revoke_openvpn_client(client_id):
    with client_operations_lock, database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ? AND protocol = 'openvpn'", (client_id,)).fetchone()
        if row is None:
            raise ValueError("OpenVPN account not found.")
        username = row["username"]
        try:
            revoke_result = subprocess.run(
                ["./easyrsa", "--batch", "revoke", username],
                cwd=str(EASYRSA_DIR), capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("OpenVPN certificate revocation failed.") from exc
        if revoke_result.returncode != 0:
            raise RuntimeError("OpenVPN certificate revocation failed.")
        try:
            crl_result = subprocess.run(
                ["./easyrsa", "--batch", "gen-crl"],
                cwd=str(EASYRSA_DIR), capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("OpenVPN certificate revocation list could not be generated.") from exc
        crl_source = EASYRSA_DIR / "pki" / "crl.pem"
        if crl_result.returncode != 0 or not crl_source.exists():
            raise RuntimeError("OpenVPN certificate revocation list could not be generated.")
        _atomic_private_write(OPENVPN_CRL_PATH, crl_source.read_text(encoding="utf-8"))
        for d in ("issued", "private"):
            for suffix in ("crt", "key"):
                f = EASYRSA_DIR / "pki" / d / (username + "." + suffix)
                if f.exists():
                    f.unlink()
        connection.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))


def create_ipsec_client(username, duration_days):
    username = validate_client_name(username)
    if duration_days is not None and (isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days < 0):
        raise ValueError("Invalid duration.")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}", username):
        raise ValueError("IPsec username: letters/digits/._- only.")
    with client_operations_lock, database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM vpn_clients WHERE username = ?", (username,)).fetchone():
            raise ValueError("That VPN account name already exists.")
        password = secrets.token_urlsafe(18)
        host = _vpn_host()
        secrets_text = IPSEC_SECRETS.read_text() if IPSEC_SECRETS.exists() else ""
        if ": RSA" not in secrets_text:
            secrets_text = ": RSA server.key\n" + secrets_text
        secrets_text = secrets_text.rstrip() + "\n" + username + ' : EAP "' + password + '"\n'
        IPSEC_SECRETS.write_text(secrets_text)
        os.chmod(str(IPSEC_SECRETS), 0o600)
        try:
            subprocess.run(["ipsec", "rereadsecrets"], capture_output=True, timeout=15, check=False)
            subprocess.run(["systemctl", "reload", "strongswan-starter"], capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        now = int(time.time())
        expires_at = now + duration_days if duration_days else None
        client_id = secrets.token_hex(16)
        salt = secrets.token_bytes(16)
        pwh = password_digest(password, salt)
        meta = json.dumps({"eap_user": username})
        connection.execute(
            "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, password_salt, password_hash, must_change_password, protocol, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'ipsec', ?)",
            (client_id, username, "ipsec:" + client_id, "ipsec:" + client_id, "ipsec:" + client_id, now, expires_at, salt, pwh, meta))
    info = ("IKEv2 / IPsec profile\n=====================\nServer:   " + host +
            "\nUsername: " + username + "\nPassword: " + password + "\nRemote ID: " + host +
            "\n\niOS: Settings > General > VPN > Add IKEv2\nAndroid: StrongSwan app\n")
    return {"id": client_id, "username": username, "protocol": "ipsec", "createdAt": now, "expiresAt": expires_at, "temporaryPassword": password}, info


def revoke_ipsec_client(client_id):
    with client_operations_lock, database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ? AND protocol = 'ipsec'", (client_id,)).fetchone()
        if row is None:
            raise ValueError("IPsec account not found.")
        username = row["username"]
        lines = IPSEC_SECRETS.read_text().splitlines()
        kept = [l for l in lines if not l.startswith(username + " :")]
        IPSEC_SECRETS.write_text("\n".join(kept).rstrip() + "\n")
        try:
            subprocess.run(["ipsec", "rereadsecrets"], capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        connection.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))


def get_openvpn_client_config(client_id):
    with database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ? AND protocol = 'openvpn'", (client_id,)).fetchone()
    if row is None:
        raise ValueError("OpenVPN account not found.")
    username = row["username"]
    cert_path = EASYRSA_DIR / "pki" / "issued" / (username + ".crt")
    key_path = EASYRSA_DIR / "pki" / "private" / (username + ".key")
    if not cert_path.exists() or not key_path.exists():
        raise ValueError("Client certificate files are missing.")
    ca = Path("/etc/openvpn/ca.crt").read_text()
    ta = Path("/etc/openvpn/ta.key").read_text()
    ovpn = ("client\ndev tun\nproto udp\nremote " + _vpn_host() + " 1194\n"
            "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
            "remote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n"
            "key-direction 1\nverb 3\n<ca>\n" + ca + "</ca>\n<cert>\n" + cert_path.read_text() +
            "</cert>\n<key>\n" + key_path.read_text() + "</key>\n<tls-auth>\n" + ta + "</tls-auth>\n")
    return username, ovpn


def get_ipsec_client_info(client_id):
    with database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ? AND protocol = 'ipsec'", (client_id,)).fetchone()
    if row is None:
        raise ValueError("IPsec account not found.")
    username = row["username"]
    secret_pattern = re.compile(rf"^{re.escape(username)}\s*:\s*EAP\s+\"([^\"]+)\"\s*$")
    try:
        secrets_text = IPSEC_SECRETS.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("IPsec credentials are unavailable.") from exc
    password = next(
        (match.group(1) for line in secrets_text.splitlines() if (match := secret_pattern.fullmatch(line))),
        None,
    )
    if password is None:
        raise RuntimeError("IPsec credentials are unavailable.")
    host = _vpn_host()
    info = (
        "IKEv2 / IPsec profile\n=====================\n"
        f"Server:   {host}\nUsername: {username}\nPassword: {password}\nRemote ID: {host}\n\n"
        "iOS: Settings > General > VPN > Add IKEv2\n"
        "Android: StrongSwan app\n"
    )
    return username, info


def toggle_firewall(enabled):
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be true or false")
    cmd = ["ufw", "--force", "enable"] if enabled else ["ufw", "disable"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "ufw command failed").strip())
    return {"enabled": enabled}


def check_tls_certificate():
    host = _vpn_host()
    try:
        r = subprocess.run(["openssl", "s_client", "-connect", _host_port(host, 443), "-servername", host, "-brief"],
                           input="", capture_output=True, text=True, timeout=10, check=False)
        out = (r.stdout or "") + (r.stderr or "")
        if "Verification: OK" in out or "Verify return code: 0" in out:
            return {"ok": True, "detail": "Valid"}
        m = re.search(r"Verification error: (.+)", out)
        return {"ok": False, "detail": m.group(1) if m else "Handshake failed"}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "detail": type(exc).__name__}


BANNER_MODE_PATH = Path("/etc/vpnfront/ssh-banner-mode")
SSHD_BANNER_DROP = Path("/etc/ssh/sshd_config.d/vpn-banner.conf")
BANNER_TEXT_PATH = Path("/etc/ssh/vpn-banner.txt")

BANNER_TEXTS = {
    0: "",
    1: "Authorized access only. Disconnect if you are not an authorized user.\n",
    2: ("#############################################\n"
        "#        AUTHORIZED ACCESS ONLY             #\n"
        "#   All activity on this system is logged   #\n"
        "#      Disconnect if unauthorized           #\n"
        "#############################################\n"),
}




def customize_banner(text):
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    if len(text) > 4096:
        raise ValueError("Banner text too long (max 4096 chars)")
    BANNER_TEXT_PATH.parent.mkdir(parents=True, exist_ok=True)
    BANNER_TEXT_PATH.write_text(text)
    os.chmod(str(BANNER_TEXT_PATH), 0o644)
    # Ensure sshd picks it up
    SSHD_BANNER_DROP.parent.mkdir(parents=True, exist_ok=True)
    SSHD_BANNER_DROP.write_text("Banner /etc/ssh/vpn-banner.txt\n")
    os.chmod(str(SSHD_BANNER_DROP), 0o644)
    # Validate config before reload
    r = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=10, check=False)
    if r.returncode != 0:
        raise RuntimeError("sshd config error: " + (r.stderr.strip() or r.stdout.strip()))
    subprocess.run(["systemctl", "reload", "ssh"], capture_output=True, timeout=15, check=False)
    # Persist mode marker
    BANNER_MODE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BANNER_MODE_PATH.write_text("custom")
    return {"text": text, "length": len(text)}


def read_banner():
    try:
        if BANNER_TEXT_PATH.exists():
            return {"text": BANNER_TEXT_PATH.read_text()}
    except OSError:
        pass
    return {"text": ""}

def set_ssh_banner_mode(mode):
    try:
        mode_int = int(mode)
    except (TypeError, ValueError):
        raise ValueError("mode must be 0, 1, or 2")
    if mode_int not in BANNER_TEXTS:
        raise ValueError("mode must be 0, 1, or 2")
    BANNER_MODE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BANNER_MODE_PATH.write_text(str(mode_int))
    if mode_int == 0:
        try:
            SSHD_BANNER_DROP.unlink(missing_ok=True)
        except OSError:
            pass
    else:
        BANNER_TEXT_PATH.write_text(BANNER_TEXTS[mode_int])
        SSHD_BANNER_DROP.parent.mkdir(parents=True, exist_ok=True)
        SSHD_BANNER_DROP.write_text("Banner /etc/ssh/vpn-banner.txt\n")
        os.chmod(str(SSHD_BANNER_DROP), 0o644)
    r = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=10, check=False)
    if r.returncode != 0:
        raise RuntimeError("sshd config error: " + (r.stderr.strip() or r.stdout.strip()))
    subprocess.run(["systemctl", "reload", "ssh"], capture_output=True, timeout=15, check=False)
    return {"mode": mode_int}




# ============================================================
# TELEMETRY
# ============================================================
BANNED_FILE = Path("/var/lib/vpnfront/banned.json")


def _read_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return default


def _write_json(path, data):
    p2 = Path(path)
    p2.parent.mkdir(parents=True, exist_ok=True)
    tmp = p2.with_suffix(p2.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(p2)


def _banned_list():
    return _read_json(BANNED_FILE, [])


def ban_ip(ip, reason=""):
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Invalid IP address.")
    if not addr.is_global:
        raise ValueError("Only public IP addresses can be banned (got a private/loopback IP).")
    # Refuse to ban our own public IP OR any currently-connected SSH client
    try:
        # VPS public IP
        if not hasattr(ban_ip, "_self_ip"):
            ban_ip._self_ip = ""
            try:
                import urllib.request
                ban_ip._self_ip = urllib.request.urlopen(
                    "https://api.ipify.org", timeout=3).read().decode().strip()
            except Exception:
                pass
        if ban_ip._self_ip and ip == ban_ip._self_ip:
            raise ValueError("Cannot ban this server's own public IP.")
        # Currently connected SSH clients (from `who` or `ss`)
        try:
            r = subprocess.run(["who"], capture_output=True, text=True, timeout=3, check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 5 and ip in parts[4]:
                    raise ValueError("Cannot ban an IP that is currently SSH'd into this server.")
        except (OSError, subprocess.TimeoutExpired):
            pass
    except ValueError:
        raise
    except Exception:
        pass
    # Refuse to ban our own public IP
    try:
        import urllib.request
        # Cache the VPS public IP for the process lifetime
        if not hasattr(ban_ip, "_self_ip"):
            ban_ip._self_ip = None
        if ban_ip._self_ip is None:
            try:
                ban_ip._self_ip = urllib.request.urlopen(
                    "https://api.ipify.org", timeout=3).read().decode().strip()
            except Exception:
                ban_ip._self_ip = ""
        if ban_ip._self_ip and ip == ban_ip._self_ip:
            raise ValueError("Refusing to ban this server's own public IP.")
    except ValueError:
        raise
    except Exception:
        pass
    items = _banned_list()
    if not any(x["ip"] == ip for x in items):
        items.append({"ip": ip, "reason": reason, "bannedAt": int(time.time())})
        _write_json(BANNED_FILE, items)
    try:
        subprocess.run(["ufw", "deny", "from", ip, "to", "any"],
                       capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return items


def unban_ip(ip):
    items = [x for x in _banned_list() if x["ip"] != ip]
    _write_json(BANNED_FILE, items)
    # Delete any matching UFW deny rules — use numbered list to be reliable
    try:
        r = subprocess.run(["ufw", "status", "numbered"],
                           capture_output=True, text=True, timeout=10, check=False)
        nums = []
        for line in (r.stdout or "").splitlines():
            if ip in line and "DENY" in line.upper():
                m = re.match(r"\[\s*(\d+)\]", line.strip())
                if m:
                    nums.append(m.group(1))
        # Delete in reverse order so numbers stay valid
        for n in sorted(nums, key=int, reverse=True):
            subprocess.run(["ufw", "--force", "delete", n],
                           capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return items


def read_metrics():
    import shutil as _sh
    def cpu_snap():
        with open("/proc/stat") as f:
            parts = [int(x) for x in f.readline().split()[1:]]
        return sum(parts), parts[3] + parts[4]
    t1, i1 = cpu_snap()
    time.sleep(0.15)
    t2, i2 = cpu_snap()
    cpu_pct = 100.0 * (1 - (i2 - i1) / max(1, t2 - t1))
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            mem[k.strip()] = int(v.split()[0])
    mem_total = mem.get("MemTotal", 0)
    mem_avail = mem.get("MemAvailable", mem.get("MemFree", 0))
    mem_used = mem_total - mem_avail
    mem_pct = 100.0 * mem_used / max(1, mem_total)
    try:
        d = _sh.disk_usage("/")
        disk_pct = 100.0 * d.used / d.total
        disk_used = d.used; disk_total = d.total
    except OSError:
        disk_pct = disk_used = disk_total = 0
    try:
        load1, load5, load15 = [float(x) for x in open("/proc/loadavg").read().split()[:3]]
    except Exception:
        load1 = load5 = load15 = 0.0
    try:
        uptime = int(float(open("/proc/uptime").read().split()[0]))
    except Exception:
        uptime = 0
    rx = tx = 0
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                parts = line.split(":")
                if len(parts) < 2: continue
                nums = parts[1].split()
                rx += int(nums[0]); tx += int(nums[8])
    except Exception:
        pass
    return {
        "cpu": round(cpu_pct, 1),
        "mem": round(mem_pct, 1),
        "memUsedMb": round(mem_used / 1024),
        "memTotalMb": round(mem_total / 1024),
        "disk": round(disk_pct, 1),
        "diskUsedGb": round(disk_used / 1e9, 1),
        "diskTotalGb": round(disk_total / 1e9, 1),
        "load1": round(load1, 2), "load5": round(load5, 2), "load15": round(load15, 2),
        "uptime": uptime,
        "netRx": rx, "netTx": tx,
    }


def read_telemetry_logs(limit=80):
    entries = []
    def add(ts, src, lvl, msg):
        entries.append({"ts": ts, "src": src, "lvl": lvl, "msg": msg[:280]})
    try:
        lines = Path("/var/log/nginx/access.log").read_text(errors="replace").splitlines()[-120:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 9:
                ip = parts[0]
                t = parts[3][1:] if len(parts) > 3 else ""
                path = parts[6] if len(parts) > 6 else "-"
                status = parts[8] if len(parts) > 8 else "-"
                # Skip API/static noise — only real client actions matter
                _noise = ("/api/telemetry/", "/api/status", "/api/adblock",
                          "/api/session", "/api/clients", "/api/banned",
                          "/api/login", "/api/logout", "/api/password",
                          "/api/banner", "/api/ssh-banner",
                          "/api/telemetry", "/status", "/healthz")
                if any(p in path for p in _noise):
                    continue
                if any(path.endswith(ext) for ext in (".css",".js",".png",".jpg",".jpeg",".svg",".ico",".woff",".woff2",".map",".txt")):
                    continue
                lvl = "err" if status and status[0] in "45" else "ok"
                add(t, "nginx", lvl, f"{ip} {path} {status}")
    except OSError:
        pass
    try:
        r = subprocess.run(["journalctl","-u","ssh","-n","25","--no-pager","--output=short-iso"],
                           capture_output=True, text=True, timeout=5, check=False)
        for line in (r.stdout or "").splitlines():
            low = line.lower()
            if "accepted password" in low or "accepted publickey" in low:
                add(line[:19], "ssh", "ok", line[25:])
            elif "failed password" in low or "invalid user" in low:
                add(line[:19], "ssh", "warn", line[25:])
            elif "disconnected" in low or "connection closed" in low:
                add(line[:19], "ssh", "info", line[25:])
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        r = subprocess.run(["journalctl","-u","vpn-admin-api","-n","15","--no-pager","--output=short-iso"],
                           capture_output=True, text=True, timeout=5, check=False)
        for line in (r.stdout or "").splitlines():
            add(line[:19], "panel", "info", line[25:])
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        r = subprocess.run(["wg","show","wg0","dump"],
                           capture_output=True, text=True, timeout=5, check=False)
        import datetime as _dt
        for line in (r.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 5 and parts[4] and parts[4] != "0":
                try:
                    hs = int(parts[4])
                    ts = _dt.datetime.utcfromtimestamp(hs).strftime("%Y-%m-%dT%H:%M:%S")
                    add(ts, "wg", "ok", "peer " + parts[0][:20] + "\u2026 handshake " + parts[2])
                except ValueError:
                    pass
    except (OSError, subprocess.TimeoutExpired):
        pass
    entries.sort(key=lambda x: x["ts"] or "", reverse=True)
    return entries[:limit]


def read_connections(caller_ip=None):
    conns = []
    now = int(time.time())
    try:
        # Map by address (10.42.0.X) — most reliable across DB variants
        wg_users = {}
        try:
            with database() as connection:
                for row in connection.execute(
                    "SELECT address, public_key, username FROM vpn_clients WHERE protocol='wireguard'"
                ):
                    addr = (row["address"] or "").split("/")[0]
                    if addr:
                        wg_users[addr] = row["username"]
                    pk = row["public_key"] or ""
                    if ":" in pk:
                        pk = pk.split(":", 1)[-1]
                    if pk:
                        wg_users[pk] = row["username"]
        except Exception:
            pass
        r = subprocess.run(["wg","show","wg0","dump"],
                           capture_output=True, text=True, timeout=5, check=False)
        for line in (r.stdout or "").splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 8:
                pk = parts[0]; ip = parts[3]
                hs = int(parts[4] or "0")
                rx = int(parts[5] or "0"); tx = int(parts[6] or "0")
                active = bool(hs and (now - hs) < 180)
                ipaddr = ip.split("/")[0]
                username = wg_users.get(ipaddr) or wg_users.get(pk) or (pk[:10] + "…")
                conns.append({"proto":"wireguard","user":username,"ip":ipaddr,
                              "since":hs or None,"active":active,"rx":rx,"tx":tx})
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    try:
        text = Path("/var/log/openvpn-status.log").read_text(errors="replace")
        for line in text.splitlines():
            if line.startswith("CLIENT_LIST"):
                cols = line.split(",")
                if len(cols) >= 8:
                    conns.append({"proto":"openvpn","user":cols[1],"ip":cols[2].split(":")[0],
                                  "since":cols[7] if len(cols) > 7 else None,
                                  "active":True,
                                  "rx":int(cols[5] or "0") if len(cols) > 5 else 0,
                                  "tx":int(cols[6] or "0") if len(cols) > 6 else 0})
    except OSError:
        pass
    try:
        r = subprocess.run(["who"], capture_output=True, text=True, timeout=5, check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 5:
                conns.append({"proto":"ssh","user":parts[0],"ip":parts[4].strip("()"),
                              "since":parts[2]+" "+parts[3],"active":True,"rx":0,"tx":0})
    except (OSError, subprocess.TimeoutExpired):
        pass
    # Mark rows coming from the caller's IP (can't self-ban)
    if caller_ip:
        for c in conns:
            if c.get("ip") == caller_ip:
                c["self"] = True
    return conns

def _remove_peer_block(config_text, public_key):
    blocks = []
    current = []
    for line in config_text.splitlines():
        if re.fullmatch(r"\s*\[[^]]+\]\s*", line) and current:
            blocks.append(current)
            current = []
        current.append(line)
    if current:
        blocks.append(current)

    kept = []
    for block in blocks:
        is_target = (
            block[0].strip().lower() == "[peer]"
            and any(re.fullmatch(rf"\s*PublicKey\s*=\s*{re.escape(public_key)}\s*", line, re.IGNORECASE) for line in block[1:])
        )
        if not is_target:
            kept.extend(block)
    return "\n".join(kept).rstrip() + "\n"




def _client_endpoint(protocol):
    host = _vpn_host()
    ports = {
        "wireguard": 51820,
        "xray": 443, "vless": 443, "vmess": 443, "trojan": 443,
        "ssh": 22,
        "openvpn": 1194, "ovpn": 1194,
        "ipsec": None, "ikev2": None,
    }
    port = ports.get((protocol or "wireguard").lower())
    return _host_port(host, port) if port else host


def list_all_clients():
    """Return every VPN client regardless of protocol."""
    expire_non_wireguard_clients()
    wireguard_clients = {
        client["id"]: client for client in list_wireguard_clients()
    }
    clients = []
    with database() as connection:
        rows = connection.execute(
            "SELECT id, username, protocol, address, created_at, expires_at, password_hash "
            "FROM vpn_clients ORDER BY created_at DESC"
        ).fetchall()
    now = int(time.time())
    for row in rows:
        row = dict(row)
        proto = (row.get("protocol") or "wireguard").lower()
        expires = row.get("expires_at")
        active = expires is None or expires > now
        client = {
            "id": row["id"],
            "username": row["username"],
            "protocol": proto,
            "address": row.get("address") or "",
            "endpoint": _client_endpoint(proto),
            "createdAt": row.get("created_at"),
            "expiresAt": expires,
            "ageSeconds": max(0, now - (row.get("created_at") or now)),
            "remainingSeconds": max(0, expires - now) if expires is not None else None,
            "active": active,
            "status": "active" if active else "expired",
            "portalReady": row.get("password_hash") is not None,
        }
        if proto == "wireguard":
            client.update(wireguard_clients.get(row["id"], {}))
            client["endpoint"] = _client_endpoint(proto)
        clients.append(client)
    return clients


def revoke_wireguard_client(client_id):
    with client_operations_lock:
        with database() as connection:
            row = connection.execute("SELECT public_key FROM vpn_clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            raise ValueError("VPN account not found.")
        try:
            config_text = WG_CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("WireGuard configuration is unavailable.") from exc
        updated_config = _remove_peer_block(config_text, row["public_key"])
        _write_wireguard_config(updated_config)
        try:
            wireguard_command(["set", WG_INTERFACE, "peer", row["public_key"], "remove"])
        except RuntimeError:
            _write_wireguard_config(config_text)
            raise
        with database() as connection:
            connection.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))


def expire_wireguard_clients(now=None):
    current_time = int(time.time()) if now is None else int(now)
    with database() as connection:
        expired = connection.execute(
            "SELECT id FROM vpn_clients WHERE COALESCE(protocol, 'wireguard') = 'wireguard' AND expires_at IS NOT NULL AND expires_at <= ?",
            (current_time,),
        ).fetchall()
    for row in expired:
        try:
            revoke_wireguard_client(row["id"])
        except (RuntimeError, ValueError) as exc:
            logger.warning("action=expire_vpn_client result=failed error=%s", type(exc).__name__)


def expire_non_wireguard_clients(now=None):
    current_time = int(time.time()) if now is None else int(now)
    revokers = {
        "xray": revoke_xray_client,
        "ssh": revoke_ssh_client,
        "openvpn": revoke_openvpn_client,
        "ipsec": revoke_ipsec_client,
    }
    with database() as connection:
        expired = connection.execute(
            "SELECT id, protocol FROM vpn_clients "
            "WHERE COALESCE(protocol, 'wireguard') != 'wireguard' "
            "AND expires_at IS NOT NULL AND expires_at <= ?",
            (current_time,),
        ).fetchall()
    for row in expired:
        revoke = revokers.get(row["protocol"])
        if revoke is None:
            continue
        try:
            revoke(row["id"])
        except Exception as exc:
            logger.warning("action=expire_vpn_client result=failed error=%s", type(exc).__name__)


def _wireguard_peer_metrics():
    try:
        dump = wireguard_command(["show", WG_INTERFACE, "dump"])
    except RuntimeError:
        return {}
    peers = {}
    for line in dump.splitlines():
        columns = line.split("\t")
        if len(columns) < 8:
            continue
        try:
            peers[columns[0]] = {
                "endpoint": columns[2] if columns[2] != "(none)" else None,
                "lastHandshake": int(columns[4]) or None,
                "bytesReceived": int(columns[5]),
                "bytesSent": int(columns[6]),
            }
        except ValueError:
            continue
    return peers


def list_wireguard_clients(now=None):
    current_time = int(time.time()) if now is None else int(now)
    expire_wireguard_clients(current_time)
    peer_metrics = _wireguard_peer_metrics()
    with database() as connection:
        rows = connection.execute(
            "SELECT id, username, public_key, address, created_at, expires_at, password_hash, route_mode FROM vpn_clients WHERE COALESCE(protocol, 'wireguard') = 'wireguard' ORDER BY created_at DESC"
        ).fetchall()
    clients = []
    for row in rows:
        metrics = peer_metrics.get(row["public_key"], {})
        handshake = metrics.get("lastHandshake")
        clients.append({
            "id": row["id"],
            "username": row["username"],
            "protocol": "wireguard",
            "routeMode": row["route_mode"] if row["route_mode"] in WG_ROUTE_MODES else "full",
            "address": row["address"],
            "createdAt": row["created_at"],
            "expiresAt": row["expires_at"],
            "durationDays": round((row["expires_at"] - row["created_at"]) / 86400) if row["expires_at"] else 0,
            "ageSeconds": max(0, current_time - row["created_at"]),
            "remainingSeconds": max(0, row["expires_at"] - current_time) if row["expires_at"] else None,
            "lastHandshake": handshake,
            "handshakeAgeSeconds": max(0, current_time - handshake) if handshake else None,
            "endpoint": metrics.get("endpoint"),
            "bytesReceived": metrics.get("bytesReceived", 0),
            "bytesSent": metrics.get("bytesSent", 0),
            "portalReady": row["password_hash"] is not None,
            "status": "expired" if row["expires_at"] and row["expires_at"] <= current_time else "connected" if handshake and 0 <= current_time - handshake <= WG_HANDSHAKE_ACTIVE_SECONDS else "idle",
        })
    return clients




# ============================================================
# PORTAL — protocol-aware account + config
# ============================================================
PORTAL_PORTS = {
    "wireguard": 51820,
    "xray": 443, "vless": 443, "vmess": 443, "trojan": 443,
    "ssh": 22,
    "openvpn": 1194, "ovpn": 1194,
    "ipsec": None, "ikev2": None,
}

PROTO_DISPLAY = {
    "wireguard": "WireGuard",
    "xray": "Xray", "vless": "Xray", "vmess": "VMess", "trojan": "Trojan",
    "ssh": "SSH",
    "openvpn": "OpenVPN", "ovpn": "OpenVPN",
    "ipsec": "IPsec", "ikev2": "IPsec",
}




# ============================================================
# SHARE URI — universal import strings per protocol
# ============================================================
def build_share_uri(protocol, username, password, host):
    """Return a scheme://... share URI for the given protocol.
    Works with v2rayNG, SSH clients, OpenVPN Import, WireGuard Import."""
    import urllib.parse as _url
    proto = (protocol or "wireguard").lower()
    pw = password or ""
    host = _host_authority(host)

    if proto == "ssh":
        # ssh://user:pass@host:22
        return "ssh://%s:%s@%s:22#SSH%%20-%s" % (
            _url.quote(username, safe=""),
            _url.quote(pw, safe=""),
            host, _url.quote(username, safe="")
        )

    if proto == "wireguard":
        # WireGuard doesn't have a URI, but wg-quick supports a config block.
        # Produce a wg:// pseudo-URI for import tools + readable config.
        return "wg://%s@%s:51820#WireGuard%%20-%s" % (
            _url.quote(username, safe=""), host, _url.quote(username, safe="")
        )

    if proto in ("openvpn", "ovpn"):
        # openvpn://user:pass@host:1194
        return "openvpn://%s:%s@%s:1194#OpenVPN%%20-%s" % (
            _url.quote(username, safe=""), _url.quote(pw, safe=""),
            host, _url.quote(username, safe="")
        )

    if proto in ("ipsec", "ikev2"):
        # ikev2://user:pass@host
        return "ikev2://%s:%s@%s#IPsec%%20-%s" % (
            _url.quote(username, safe=""), _url.quote(pw, safe=""),
            host, _url.quote(username, safe="")
        )

    if proto in ("xray", "vless", "vmess", "trojan"):
        try:
            with database() as _c:
                row = _c.execute(
                    "SELECT public_key, metadata FROM vpn_clients WHERE username = ? AND protocol IN ('xray','vless','vmess','trojan')",
                    (username,),
                ).fetchone()
            if row is None:
                return ""
            try:
                metadata = json.loads(row["metadata"] or "{}")
            except json.JSONDecodeError:
                metadata = {}
            client_uuid = metadata.get("uuid") or row["public_key"] or ""
            if ":" in client_uuid:
                client_uuid = client_uuid.split(":", 1)[-1]
            try:
                uuid.UUID(client_uuid)
            except (AttributeError, ValueError):
                return ""
            transport_id = {
                "vmess": "vmess-ws",
                "trojan": "trojan-ws",
            }.get(proto, "vless-xhttp")
            transport = next(
                (item for item in XRAY_TRANSPORTS if item["id"] == transport_id),
                None,
            )
            if transport is not None:
                return _share_link(transport, client_uuid, host)
        except Exception:
            pass
        return ""

    return ""



def get_client_account(client_id):
    """Generic account info for the portal — any protocol."""
    with database() as connection:
        row = connection.execute(
            "SELECT id, username, protocol, address, created_at, expires_at "
            "FROM vpn_clients WHERE id = ?",
            (client_id,),
        ).fetchone()
    if row is None:
        raise ValueError("VPN account not found.")
    now = int(time.time())
    if row["expires_at"] is not None and row["expires_at"] <= now:
        raise ExpiredClientError("This VPN account has expired.")
    proto = (row["protocol"] or "wireguard").lower()
    wireguard_account = (
        get_wireguard_client_account(row["id"], now)
        if proto == "wireguard" else {}
    )
    host = _vpn_host()
    port = PORTAL_PORTS.get(proto)
    endpoint = _host_port(host, port) if port else host
    # Protocol-specific display value for the "address" field
    address = (row["address"] or "")
    # For SSH/Xray/OpenVPN/IPsec we stored "ssh:xxx" style placeholder — clean it
    if ":" in address and proto != "wireguard":
        prefix = address.split(":", 1)[0].lower()
        if prefix in ("ssh", "xray", "ovpn", "openvpn", "ipsec", "legacy"):
            address = row["username"]   # show the username instead
    return {
        "id": row["id"],
        "username": row["username"],
        "protocol": proto,
        "protocolLabel": PROTO_DISPLAY.get(proto, proto.upper()),
        "address": address,
        "endpoint": endpoint,
        "host": host,
        "port": port,
        "createdAt": row["created_at"],
        "expiresAt": row["expires_at"],
        "active": True,
        "ageSeconds": max(0, now - (row["created_at"] or now)),
        "remainingSeconds": (max(0, row["expires_at"] - now) if row["expires_at"] else None),
        "durationDays": (
            max(1, round((row["expires_at"] - row["created_at"]) / 86400))
            if row["expires_at"] else None
        ),
        "status": wireguard_account.get("status", "active"),
        "handshakeAgeSeconds": wireguard_account.get("handshakeAgeSeconds"),
        "bytesReceived": wireguard_account.get("bytesReceived", 0),
        "bytesSent": wireguard_account.get("bytesSent", 0),
    }




# ============================================================
# XRAY TRANSPORTS — all share links
# ============================================================
XRAY_TRANSPORTS = [
    {"id": "vless-xhttp", "label": "XHTTP",      "kind": "path",  "path": XRAY_XHTTP_PATH},
    {"id": "vless-ws",    "label": "WebSocket",  "kind": "path",  "path": "/saeka-vless-ws"},
    {"id": "vless-grpc",  "label": "gRPC",       "kind": "path",  "service": "saeka-vless-grpc"},
    {"id": "vless-tcp",   "label": "TCP",        "kind": "port",  "port": 10443},
    {"id": "vmess-ws",    "label": "VMess WS",   "kind": "path",  "path": "/saeka-vmess-ws", "protocol": "vmess"},
    {"id": "trojan-ws",   "label": "Trojan WS",  "kind": "path",  "path": "/saeka-trojan-ws", "protocol": "trojan"},
]


def _share_link(t, uuid, host):
    authority = _host_authority(host)
    if t.get("protocol") == "vmess":
        import base64 as _b64
        payload = {
            "v": "2", "ps": "Saeka-" + t["label"],
            "add": host, "port": "443", "id": uuid, "aid": "0",
            "net": "ws", "type": "none", "host": host,
            "path": t["path"], "tls": "tls", "sni": host,
        }
        return "vmess://" + _b64.b64encode(json.dumps(payload).encode()).decode()
    if t.get("protocol") == "trojan":
        return f"trojan://{uuid}@{authority}:443?security=tls&sni={host}&type=ws&path={t['path']}&host={host}#Saeka-{t['label']}"
    # vless
    if t["kind"] == "path":
        if t["id"] == "vless-grpc":
            return f"vless://{uuid}@{authority}:443?encryption=none&security=tls&sni={host}&type=grpc&serviceName={t['service']}#Saeka-{t['label']}"
        if t["id"] == "vless-h2":
            return f"vless://{uuid}@{authority}:443?encryption=none&security=tls&sni={host}&type=http&path=%2F{t['path'].lstrip('/')}&host={host}#Saeka-{t['label']}"
        net = "splithttp" if "xhttp" in t["id"] else "ws"
        return f"vless://{uuid}@{authority}:443?encryption=none&security=tls&sni={host}&type={net}&path=%2F{t['path'].lstrip('/')}&host={host}#Saeka-{t['label']}"
    # direct TCP/KCP/QUIC
    net = "tcp" if t["id"] == "vless-tcp" else ("kcp" if t["id"] == "vless-kcp" else "quic")
    return f"vless://{uuid}@{_host_port(host, t['port'])}?encryption=none&security=none&type={net}#Saeka-{t['label']}"


def xray_transports(uuid):
    host = _vpn_host()
    out = []
    for t in XRAY_TRANSPORTS:
        item = dict(t)
        item["share"] = _share_link(t, uuid, host)
        out.append(item)
    return out


def get_xray_client_transports(client_id):
    with database() as connection:
        row = connection.execute(
            "SELECT protocol, metadata FROM vpn_clients WHERE id = ?",
            (client_id,),
        ).fetchone()
    if row is None or row["protocol"] not in {"xray", "vless", "vmess", "trojan"}:
        raise ValueError("Xray account not found.")
    try:
        metadata = json.loads(row["metadata"] or "{}")
        client_uuid = str(uuid.UUID(metadata["uuid"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Xray account credentials are invalid.") from exc
    return xray_transports(client_uuid)



def get_client_config(client_id):
    """Dispatch config/credentials generation by protocol."""
    with database() as connection:
        row = connection.execute(
            "SELECT protocol FROM vpn_clients WHERE id = ?", (client_id,)
        ).fetchone()
    if row is None:
        raise ValueError("VPN account not found.")
    proto = (row["protocol"] or "wireguard").lower()
    if proto == "wireguard":
        return get_wireguard_client_config(client_id)
    if proto == "xray" or proto in ("vless", "vmess", "trojan"):
        return get_xray_client_share(client_id)
    if proto == "ssh":
        return get_ssh_client_info(client_id)
    if proto == "openvpn" or proto == "ovpn":
        return get_openvpn_client_config(client_id)
    if proto == "ipsec" or proto == "ikev2":
        return get_ipsec_client_info(client_id)
    raise ValueError("Unknown protocol: " + proto)




# ============================================================
# CONFIG EXPORT — filename + content-type per protocol
# ============================================================
CONFIG_META = {
    "wireguard": ("conf", "text/plain; charset=utf-8"),
    "openvpn":   ("ovpn", "application/x-openvpn-profile"),
    "ovpn":      ("ovpn", "application/x-openvpn-profile"),
    "xray":      ("txt",  "text/plain; charset=utf-8"),
    "vless":     ("txt",  "text/plain; charset=utf-8"),
    "vmess":     ("txt",  "text/plain; charset=utf-8"),
    "trojan":    ("txt",  "text/plain; charset=utf-8"),
    "ssh":       ("txt",  "text/plain; charset=utf-8"),
    "ipsec":     ("txt", "text/plain; charset=utf-8"),
    "ikev2":     ("txt", "text/plain; charset=utf-8"),
}


def get_config_meta(protocol):
    """Return (extension, content-type, human name) for the protocol."""
    key = (protocol or "wireguard").lower()
    ext, ctype = CONFIG_META.get(key, ("txt", "text/plain; charset=utf-8"))
    label = PROTO_DISPLAY.get(key, key.upper()) if "PROTO_DISPLAY" in globals() else key.upper()
    return ext, ctype, label


def sanitize_filename(name):
    import re as _re
    return _re.sub(r"[^A-Za-z0-9._-]", "_", (name or "config"))[:64] or "config"


def get_config_extension(protocol):
    return {
        "wireguard": "conf",
        "openvpn": "ovpn", "ovpn": "ovpn",
        "xray": "txt", "vless": "txt", "vmess": "txt", "trojan": "txt",
        "ssh": "txt",
        "ipsec": "txt", "ikev2": "txt",
    }.get((protocol or "wireguard").lower(), "txt")


def get_wireguard_client_account(client_id, now=None):
    for client in list_wireguard_clients(now):
        if client["id"] == client_id:
            return client
    raise ValueError("VPN account not found or has expired.")


def get_wireguard_client_config(client_id):
    with database() as connection:
        row = connection.execute(
            "SELECT username, private_key, address, expires_at, route_mode FROM vpn_clients WHERE id = ?",
            (client_id,),
        ).fetchone()
    if row is None:
        raise ValueError("VPN account not found.")
    if row["expires_at"] is not None and row["expires_at"] <= int(time.time()):
        raise ExpiredClientError("This VPN account has expired.")
    endpoint = _wireguard_endpoint()
    server_public_key = wireguard_command(["show", WG_INTERFACE, "public-key"])
    return row["username"], (
        "[Interface]\n"
        f"PrivateKey = {row['private_key']}\n"
        f"Address = {row['address']}/32\n"
        f"DNS = {WG_GATEWAY_ADDRESS}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {WG_ROUTE_MODES.get(row['route_mode'], WG_ROUTE_MODES['full'])}\n"
        "PersistentKeepalive = 25\n"
    )


def login_allowed(client_ip):
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with login_attempts_lock:
        attempts = [stamp for stamp in login_attempts.get(client_ip, []) if stamp >= cutoff]
        login_attempts[client_ip] = attempts
        return len(attempts) < LOGIN_FAILURE_LIMIT


def record_login_failure(client_ip):
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with login_attempts_lock:
        attempts = [stamp for stamp in login_attempts.get(client_ip, []) if stamp >= cutoff]
        attempts.append(time.time())
        login_attempts[client_ip] = attempts


def clear_login_failures(client_ip):
    with login_attempts_lock:
        login_attempts.pop(client_ip, None)


def resolve_service_unit(service_key):
    result = subprocess.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    available = {line.split()[0] for line in (result.stdout or "").splitlines() if line.split()}
    for candidate in SERVICE_UNITS[service_key]:
        if candidate in available:
            if candidate.endswith("@.service"):
                instance = "wg0" if service_key == "wireguard" else "server"
                return candidate.replace("@.service", f"@{instance}.service")
            return candidate
    return DEFAULT_SERVICE_UNITS[service_key]


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "VPNAdmin"
    sys_version = ""

    def log_message(self, message, *args):
        logger.info("%s %s", self.client_address[0], message % args)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        super().end_headers()

    def send_json(self, status, payload, headers=()):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status, body, content_type, headers=()):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Expected an application/json request.")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request length.") from exc
        if size < 0 or size > MAX_BODY_SIZE:
            raise ValueError("Request body is too large.")
        try:
            value = json.loads(self.rfile.read(size))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid JSON request.") from exc
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object.")
        return value

    def origin_is_valid(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        scheme = self.headers.get("X-Forwarded-Proto", "https")
        return hmac.compare_digest(origin.rstrip("/"), f"{scheme}://{host}".rstrip("/"))

    def get_session(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is None:
            return None
        token_hash = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).digest()
        with database() as connection:
            row = connection.execute(
                "SELECT sessions.username, sessions.csrf_token, sessions.expires_at, admins.must_change_password "
                "FROM sessions JOIN admins USING(username) WHERE sessions.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is not None and row["expires_at"] < int(time.time()):
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
        if row is None:
            return None
        return {
            "username": row["username"],
            "csrf_token": row["csrf_token"],
            "must_change_password": bool(row["must_change_password"]),
            "token_hash": token_hash,
        }

    def get_client_session(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(CLIENT_SESSION_COOKIE)
        if morsel is None:
            return None
        token_hash = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).digest()
        with database() as connection:
            row = connection.execute(
                "SELECT client_sessions.client_id, vpn_clients.username, client_sessions.csrf_token, client_sessions.expires_at, vpn_clients.must_change_password "
                "FROM client_sessions JOIN vpn_clients ON vpn_clients.id = client_sessions.client_id WHERE client_sessions.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is not None and row["expires_at"] < int(time.time()):
                connection.execute("DELETE FROM client_sessions WHERE token_hash = ?", (token_hash,))
                return None
        if row is None:
            return None
        return {
            "client_id": row["client_id"],
            "username": row["username"],
            "csrf_token": row["csrf_token"],
            "must_change_password": bool(row["must_change_password"]),
            "token_hash": token_hash,
        }

    def require_client_session(self, allow_forced_password_change=False):
        session = self.get_client_session()
        if session is None:
            self.send_json(401, {"error": "Client sign-in required."})
            return None
        if session["must_change_password"] and not allow_forced_password_change:
            self.send_json(428, {"error": "Change your temporary password before continuing."})
            return None
        return session

    def require_client_csrf(self, session):
        supplied = self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(supplied, session["csrf_token"]):
            self.send_json(403, {"error": "Invalid CSRF token."})
            return False
        return True

    def require_session(self, allow_forced_password_change=False):
        session = self.get_session()
        if session is None:
            self.send_json(401, {"error": "Authentication required."})
            return None
        if session["must_change_password"] and not allow_forced_password_change:
            self.send_json(428, {"error": "Change the initial password before continuing."})
            return None
        return session

    def require_csrf(self, session):
        supplied = self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(supplied, session["csrf_token"]):
            self.send_json(403, {"error": "Invalid CSRF token."})
            return False
        return True

    def set_session_cookie(self, token):
        return ("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Strict")

    def clear_session_cookie(self):
        return ("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")

    def set_client_session_cookie(self, token):
        return ("Set-Cookie", f"{CLIENT_SESSION_COOKIE}={token}; Path=/; Max-Age={CLIENT_SESSION_TTL}; HttpOnly; Secure; SameSite=Strict")

    def clear_client_session_cookie(self):
        return ("Set-Cookie", f"{CLIENT_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/portal/session":
            expire_wireguard_clients()
            session = self.get_client_session()
            if session is None:
                self.send_json(200, {"authenticated": False, "maintenance": read_maintenance_state()})
            else:
                client_ip = self.headers.get("X-Real-IP") or self.client_address[0]
                self.send_json(200, {
                    "authenticated": True,
                    "username": session["username"],
                    "csrfToken": session["csrf_token"],
                    "mustChangePassword": session["must_change_password"],
                    "clientIp": client_ip,
                    "maintenance": read_maintenance_state(),
                })
            return

        if path == "/api/portal/share":
            session = self.require_client_session()
            if session is None:
                return
            try:
                with database() as _c:
                    row = _c.execute(
                        "SELECT username, protocol, password_salt, password_hash FROM vpn_clients WHERE id = ?",
                        (session["client_id"],),
                    ).fetchone()
                if not row:
                    self.send_json(404, {"error": "Account not found."})
                    return
                host = _vpn_host()
                # We do NOT store the plaintext password. Show placeholder.
                uri = build_share_uri(row["protocol"], row["username"], "", host)
                self.send_json(200, {"uri": uri, "username": row["username"], "protocol": row["protocol"]})
            except Exception:
                self.send_json(503, {"error": "share unavailable"})
            return
        if path == "/api/portal/transports":
            session = self.require_client_session()
            if session is None:
                return
            try:
                self.send_json(200, {"transports": get_xray_client_transports(session["client_id"])})
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
            except (OSError, RuntimeError, sqlite3.Error):
                self.send_json(503, {"error": "transports unavailable"})
            return
        if path == "/api/portal/account":
            session = self.require_client_session()
            if session is None:
                return
            try:
                self.send_json(200, {"account": get_client_account(session["client_id"])})
            except ExpiredClientError as exc:
                self.send_json(410, {"error": str(exc)}, [self.clear_client_session_cookie()])
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
            return

        if path == "/api/portal/config":
            session = self.require_client_session()
            if session is None:
                return
            try:
                with database() as _c:
                    _row = _c.execute(
                        "SELECT username, protocol FROM vpn_clients WHERE id = ?",
                        (session["client_id"],),
                    ).fetchone()
                if not _row:
                    self.send_json(404, {"error": "Account not found."})
                    return
                username = _row["username"]
                proto = (_row["protocol"] or "wireguard").lower()
                config = get_client_config(session["client_id"])
                # Some helpers return (username, config) tuple
                if isinstance(config, tuple):
                    username, config = config
                ext, ctype, label = get_config_meta(proto)
                fname = sanitize_filename(username) + "." + ext
            except ExpiredClientError as exc:
                self.send_json(410, {"error": str(exc)}, [self.clear_client_session_cookie()])
                return
            except (ValueError, RuntimeError) as exc:
                self.send_json(503, {"error": str(exc)})
                return
            self.send_text(
                200,
                config,
                ctype,
                [("Content-Disposition", f'attachment; filename="{fname}"')],
            )
            return

        if path == "/api/session":
            session = self.get_session()
            if session is None:
                self.send_json(200, {"authenticated": False})
            else:
                self.send_json(200, {
                    "authenticated": True,
                    "username": session["username"],
                    "csrfToken": session["csrf_token"],
                    "mustChangePassword": session["must_change_password"],
                })
            return

        if path == "/api/status":
            if self.require_session() is None:
                return
            try:
                payload = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.send_json(503, {"error": "Node status is not available."})
                return
            self.send_json(200, payload)
            return

        if path == "/api/banner":
            if self.require_session() is None:
                return
            self.send_json(200, {"banner": read_banner()})
            return
        if path == "/api/telemetry/metrics":
            if self.require_session() is None: return
            try: self.send_json(200, {"metrics": read_metrics()})
            except Exception as exc: self.send_json(503, {"error": "metrics unavailable"})
            return
        if path == "/api/telemetry/logs":
            if self.require_session() is None: return
            try: self.send_json(200, {"logs": read_telemetry_logs()})
            except Exception: self.send_json(503, {"error": "logs unavailable"})
            return
        if path == "/api/telemetry/connections":
            if self.require_session() is None: return
            try:
                caller = self.headers.get("X-Real-IP") or self.client_address[0]
                self.send_json(200, {"connections": read_connections(caller_ip=caller)})
            except Exception: self.send_json(503, {"error": "connections unavailable"})
            return
        if path == "/api/telemetry/banned":
            if self.require_session() is None: return
            self.send_json(200, {"banned": _banned_list()})
            return
        if path == "/api/adblock":
            if self.require_session() is None:
                return
            self.send_json(200, {"adblock": read_adblock_state()})
            return
        if path == "/api/maintenance":
            if self.require_session() is None:
                return
            self.send_json(200, {"maintenance": read_maintenance_state()})
            return

        if path == "/api/users":
            if self.require_session() is None:
                return
            self.send_json(200, {"users": list_admins()})
            return

        client_config_match = re.fullmatch(r"/api/clients/([a-f0-9]{32})/config", path)
        if client_config_match:
            if self.require_session() is None:
                return
            try:
                cid = client_config_match.group(1)
                with database() as _c:
                    _row = _c.execute(
                        "SELECT username, protocol FROM vpn_clients WHERE id = ?",
                        (cid,),
                    ).fetchone()
                if not _row:
                    self.send_json(404, {"error": "Account not found."})
                    return
                username = _row["username"]
                proto = (_row["protocol"] or "wireguard").lower()
                config = get_client_config(cid)
                if isinstance(config, tuple):
                    username, config = config
                ext, ctype, label = get_config_meta(proto)
                fname = sanitize_filename(username) + "." + ext
            except ExpiredClientError as exc:
                self.send_json(410, {"error": str(exc)})
                return
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
                return
            except RuntimeError as exc:
                self.send_json(503, {"error": str(exc)})
                return
            self.send_text(
                200,
                config,
                ctype,
                [("Content-Disposition", f'attachment; filename="{fname}"')],
            )
            return

        if path == "/api/clients":
            if self.require_session() is None:
                return
            try:
                self.send_json(200, {"clients": list_all_clients()})
            except (OSError, sqlite3.Error):
                self.send_json(503, {"error": "VPN account data is unavailable."})
            return

        self.send_json(404, {"error": "Not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.origin_is_valid():
            self.send_json(403, {"error": "Cross-origin request rejected."})
            return
        try:
            payload = self.read_json()
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return

        if path == "/api/portal/login":
            self.client_login(payload)
            return

        if path == "/api/portal/logout":
            session = self.require_client_session(allow_forced_password_change=True)
            if session is None or not self.require_client_csrf(session):
                return
            with database() as connection:
                connection.execute("DELETE FROM client_sessions WHERE token_hash = ?", (session["token_hash"],))
            self.send_json(200, {"ok": True}, [self.clear_client_session_cookie()])
            return

        if path == "/api/portal/password":
            self.change_client_password(payload)
            return

        if path == "/api/login":
            self.login(payload)
            return

        if path == "/api/logout":
            session = self.require_session(allow_forced_password_change=True)
            if session is None or not self.require_csrf(session):
                return
            with database() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],))
            self.send_json(200, {"ok": True}, [self.clear_session_cookie()])
            return

        if path == "/api/password":
            self.change_password(payload)
            return

        session = self.require_session()
        if session is None or not self.require_csrf(session):
            return

        if path == "/api/firewall":
            enabled = payload.get("enabled")
            try:
                state = toggle_firewall(enabled)
            except (ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                self.send_json(400, {"error": str(exc)})
                return
            logger.info("admin=%s action=firewall_toggle enabled=%s", session["username"], enabled)
            self.send_json(200, {"firewall": state})
            return
        if path == "/api/tls-check":
            result = check_tls_certificate()
            logger.info("admin=%s action=tls_check ok=%s", session["username"], result.get("ok"))
            self.send_json(200, {"tls": result})
            return
        if path == "/api/telemetry/ban":
            ip = payload.get("ip", "")
            reason = payload.get("reason", "")
            try:
                items = ban_ip(ip, reason)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            logger.info("admin=%s action=ban_ip ip=%s", session["username"], ip)
            self.send_json(200, {"banned": items})
            return
        if path == "/api/banner":
            try:
                text = payload.get("text", "")
                result = customize_banner(text)
            except (ValueError, RuntimeError) as exc:
                self.send_json(400, {"error": str(exc)})
                return
            logger.info("admin=%s action=banner_customize length=%s", session["username"], len(text))
            self.send_json(200, {"banner": result})
            return
        if path == "/api/ssh-banner":
            mode = payload.get("mode")
            try:
                state = set_ssh_banner_mode(mode)
            except (ValueError, RuntimeError) as exc:
                self.send_json(400, {"error": str(exc)})
                return
            logger.info("admin=%s action=ssh_banner mode=%s", session["username"], mode)
            self.send_json(200, {"sshBanner": state})
            return
        if path == "/api/adblock":
            enabled = payload.get("enabled")
            try:
                state = set_adblock_enabled(
                    enabled,
                    level=payload.get("level"),
                    blocked_domains=payload.get("blockedDomains"),
                )
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                logger.warning("admin=%s action=adblock_toggle enabled=%s error=%s", session["username"], enabled, type(exc).__name__)
                self.send_json(503, {"error": str(exc)})
                return
            logger.info("admin=%s action=adblock_toggle enabled=%s", session["username"], enabled)
            self.send_json(200, {"adblock": state})
            return
        if path == "/api/maintenance":
            try:
                state = set_maintenance_state(
                    payload.get("enabled"),
                    payload.get("message", ""),
                    payload.get("blockInternet", False),
                )
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                self.send_json(503, {"error": str(exc)})
                return
            logger.info("admin=%s action=maintenance_notice enabled=%s", session["username"], state["enabled"])
            self.send_json(200, {"maintenance": state})
            return

        if path == "/api/users":
            try:
                username = payload.get("username")
                password = payload.get("password")
                add_admin(username, password, must_change_password=True)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            logger.info("admin=%s action=add_admin target=%s", session["username"], username)
            self.send_json(201, {"ok": True, "username": username})
            return

        if path == "/api/clients":
            username = payload.get("username")
            provided_password = payload.get("password")
            skip_password = payload.get("skipPassword", False)
            try:
                username = validate_client_name(username)
                duration_days = parse_client_duration(payload)
                protocol = payload.get("protocol", "wireguard") or "wireguard"
                if not isinstance(protocol, str):
                    raise ValueError("Unknown VPN protocol.")
                protocol = protocol.lower()
                if protocol not in {"wireguard", "xray", "ssh", "openvpn", "ipsec"}:
                    raise ValueError("Unsupported VPN protocol.")
                route_mode = validate_wireguard_route_mode(payload.get("routeMode", "full"))
                if not isinstance(skip_password, bool):
                    raise ValueError("skipPassword must be true or false.")
                if skip_password and provided_password is not None:
                    raise ValueError("A password cannot be supplied when portal login is disabled.")
                if provided_password is not None:
                    validate_password(provided_password)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return

            try:
                if protocol == "xray":
                    client, config = create_xray_client(username, duration_days)
                elif protocol == "ssh":
                    client, config = create_ssh_client(username, duration_days)
                elif protocol == "openvpn":
                    client, config = create_openvpn_client(username, duration_days)
                elif protocol == "ipsec":
                    client, config = create_ipsec_client(username, duration_days)
                elif protocol == "wireguard":
                    client, config = create_wireguard_client(username, duration_days, route_mode)
                else:
                    raise ValueError("Unsupported VPN protocol.")
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            except RuntimeError as exc:
                logger.warning("admin=%s action=create_vpn_client result=failed protocol=%s error=%s", session["username"], protocol, type(exc).__name__)
                self.send_json(503, {"error": str(exc)})
                return
            # Apply user-supplied portal password (optional)
            try:
                if skip_password:
                    with database() as conn:
                        conn.execute(
                            "UPDATE vpn_clients SET password_salt=NULL, password_hash=NULL, must_change_password=0 WHERE id=?",
                            (client["id"],),
                        )
                    client["temporaryPassword"] = None
                elif provided_password is not None:
                    salt = secrets.token_bytes(16)
                    pwh = password_digest(provided_password, salt)
                    with database() as conn:
                        conn.execute(
                            "UPDATE vpn_clients SET password_salt=?, password_hash=?, must_change_password=0 WHERE id=?",
                            (salt, pwh, client["id"]),
                        )
                    client["temporaryPassword"] = provided_password
            except sqlite3.Error:
                pass

            logger.info("admin=%s action=create_vpn_client target=%s protocol=%s", session["username"], username, protocol)
            self.send_json(201, {"client": client, "config": config})
            return

        client_password_match = re.fullmatch(r"/api/clients/([a-f0-9]{32})/password", path)
        if client_password_match:
            try:
                username, temporary_password = reset_client_portal_password(client_password_match.group(1))
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
                return
            logger.info("admin=%s action=reset_vpn_client_password target=%s", session["username"], username)
            self.send_json(200, {"username": username, "temporaryPassword": temporary_password})
            return

        service_match = re.fullmatch(r"/api/services/([a-z]+)/restart", path)
        if service_match:
            service_key = service_match.group(1)
            if service_key not in SERVICE_UNITS:
                self.send_json(404, {"error": "Unknown service."})
                return
            try:
                unit = resolve_service_unit(service_key)
                result = subprocess.run(
                    ["systemctl", "restart", unit.removesuffix(".service")],
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("admin=%s action=restart service=%s error=%s", session["username"], service_key, type(exc).__name__)
                self.send_json(502, {"error": "Service restart failed. Check the system journal."})
                return
            if result.returncode != 0:
                logger.warning("admin=%s action=restart service=%s result=failed", session["username"], service_key)
                self.send_json(502, {"error": "Service restart failed. Check the system journal."})
                return
            logger.info("admin=%s action=restart service=%s result=ok", session["username"], service_key)
            try:
                subprocess.run(
                    ["systemctl", "start", "vpn-status-refresh.service"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                logger.warning("admin=%s action=refresh_status result=failed", session["username"])
            self.send_json(200, {"ok": True, "service": service_key})
            return

        self.send_json(404, {"error": "Not found."})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if not self.origin_is_valid():
            self.send_json(403, {"error": "Cross-origin request rejected."})
            return
        session = self.require_session()
        if session is None or not self.require_csrf(session):
            return
        ban_match = re.fullmatch(r"/api/telemetry/ban/([^/]+)", path)
        if ban_match:
            from urllib.parse import unquote as _unq
            ip = _unq(ban_match.group(1))
            items = unban_ip(ip)
            logger.info("admin=%s action=unban_ip ip=%s", session["username"], ip)
            self.send_json(200, {"banned": items})
            return
        client_match = re.fullmatch(r"/api/clients/([a-f0-9]{32})", path)
        if client_match:
            cid = client_match.group(1)
            try:
                proto = get_client_protocol(cid)
                if proto == "xray":
                    revoke_xray_client(cid)
                elif proto == "ssh":
                    revoke_ssh_client(cid)
                elif proto == "openvpn":
                    revoke_openvpn_client(cid)
                elif proto == "ipsec":
                    revoke_ipsec_client(cid)
                else:
                    revoke_wireguard_client(cid)
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
                return
            except RuntimeError as exc:
                logger.warning("admin=%s action=revoke_vpn_client result=failed error=%s", session["username"], type(exc).__name__)
                self.send_json(503, {"error": str(exc)})
                return
            logger.info("admin=%s action=revoke_vpn_client id=%s protocol=%s", session["username"], cid, proto)
            self.send_json(200, {"ok": True})
            return
        match = re.fullmatch(r"/api/users/([^/]+)", path)
        if not match:
            self.send_json(404, {"error": "Not found."})
            return
        username = unquote(match.group(1))
        try:
            delete_admin(username, session["username"])
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        logger.info("admin=%s action=remove_admin target=%s", session["username"], username)
        self.send_json(200, {"ok": True})

    def login(self, payload):
        client_ip = self.headers.get("X-Real-IP") or self.client_address[0]
        if not login_allowed(client_ip):
            self.send_json(429, {"error": "Too many failed sign-in attempts. Try again later."})
            return
        username = payload.get("username", "")
        password = payload.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            user = None
        else:
            user = verify_password(username, password)
        if user is None:
            record_login_failure(client_ip)
            self.send_json(401, {"error": "Username or password is incorrect."})
            return
        clear_login_failures(client_ip)
        token, csrf_token = new_session(username)
        logger.info("admin=%s action=login", username)
        self.send_json(200, {
            "authenticated": True,
            "username": username,
            "csrfToken": csrf_token,
            "mustChangePassword": user["must_change_password"],
        }, [self.set_session_cookie(token)])

    def client_login(self, payload):
        client_ip = f"client:{self.headers.get('X-Real-IP') or self.client_address[0]}"
        if not login_allowed(client_ip):
            self.send_json(429, {"error": "Too many failed sign-in attempts. Try again later."})
            return
        username = payload.get("username", "")
        password = payload.get("password", "")
        user = verify_client_password(username, password) if isinstance(username, str) and isinstance(password, str) else None
        if user is None:
            record_login_failure(client_ip)
            self.send_json(401, {"error": "Username or password is incorrect."})
            return
        clear_login_failures(client_ip)
        token, csrf_token = new_client_session(user["id"])
        logger.info("vpn_client=%s action=portal_login", username)
        self.send_json(200, {
            "authenticated": True,
            "username": username,
            "csrfToken": csrf_token,
            "mustChangePassword": user["must_change_password"],
        }, [self.set_client_session_cookie(token)])

    def change_client_password(self, payload):
        session = self.require_client_session(allow_forced_password_change=True)
        if session is None or not self.require_client_csrf(session):
            return
        old_password = payload.get("oldPassword", "")
        new_password = payload.get("newPassword", "")
        user = verify_client_password(session["username"], old_password) if isinstance(old_password, str) else None
        if user is None or user["id"] != session["client_id"]:
            self.send_json(401, {"error": "Current password is incorrect."})
            return
        try:
            validate_password(new_password)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        salt = secrets.token_bytes(16)
        digest = password_digest(new_password, salt)
        with database() as connection:
            connection.execute(
                "UPDATE vpn_clients SET password_salt = ?, password_hash = ?, must_change_password = 0 WHERE id = ?",
                (salt, digest, session["client_id"]),
            )
            connection.execute("DELETE FROM client_sessions WHERE client_id = ?", (session["client_id"],))
        token, csrf_token = new_client_session(session["client_id"])
        logger.info("vpn_client=%s action=portal_password_change", session["username"])
        self.send_json(200, {
            "ok": True,
            "username": session["username"],
            "csrfToken": csrf_token,
            "mustChangePassword": False,
        }, [self.set_client_session_cookie(token)])

    def change_password(self, payload):
        session = self.require_session(allow_forced_password_change=True)
        if session is None or not self.require_csrf(session):
            return
        old_password = payload.get("oldPassword", "")
        new_password = payload.get("newPassword", "")
        user = verify_password(session["username"], old_password) if isinstance(old_password, str) else None
        if user is None:
            self.send_json(401, {"error": "Current password is incorrect."})
            return
        try:
            validate_password(new_password)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        salt = secrets.token_bytes(16)
        digest = password_digest(new_password, salt)
        with database() as connection:
            connection.execute(
                "UPDATE admins SET salt = ?, password_hash = ?, must_change_password = 0 WHERE username = ?",
                (salt, digest, session["username"]),
            )
            connection.execute("DELETE FROM sessions WHERE username = ?", (session["username"],))
        token, csrf_token = new_session(session["username"])
        logger.info("admin=%s action=change_password", session["username"])
        self.send_json(200, {
            "ok": True,
            "username": session["username"],
            "csrfToken": csrf_token,
            "mustChangePassword": False,
        }, [self.set_session_cookie(token)])


def serve(host, port):
    address = ipaddress.ip_address(host)
    if not address.is_loopback:
        raise ValueError("The admin API must bind to a loopback address.")
    init_database()
    if read_maintenance_state()["blockInternet"]:
        set_vpn_forwarding_block(True)
    threading.Thread(target=wireguard_expiry_worker, daemon=True, name="wireguard-expiry").start()
    server = ThreadingHTTPServer((host, port), AdminHandler)
    server.daemon_threads = True
    logger.info("Admin API listening on %s:%s", host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def wireguard_expiry_worker():
    while True:
        try:
            expire_wireguard_clients()
            expire_non_wireguard_clients()
        except Exception as exc:
            logger.warning("action=expire_vpn_clients error=%s", type(exc).__name__)
        time.sleep(30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--init-admin", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.init_admin:
        init_database()
        with database() as connection:
            existing_admins = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if existing_admins:
            print("Admin database already initialized; existing accounts were preserved.")
            return
        username = os.environ.get("VPN_ADMIN_INITIAL_USER", "saeka")
        password = os.environ.get("VPN_ADMIN_INITIAL_PASSWORD", "")
        if not password:
            parser.error("VPN_ADMIN_INITIAL_PASSWORD must be provided through the environment.")
        created = bootstrap_admin(username, password)
        print("Initial admin created; password change is required on first sign-in." if created else "Admin database already initialized; existing accounts were preserved.")
        return
    serve(args.host, args.port)


if __name__ == "__main__":
    main()