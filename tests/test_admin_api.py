import http.client
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer


MODULE_PATH = Path(__file__).resolve().parents[1] / "admin-api.py"
SPEC = importlib.util.spec_from_file_location("admin_api", MODULE_PATH)
admin_api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admin_api)


class AdminApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = admin_api.DB_PATH
        self.original_status_path = admin_api.STATUS_PATH
        self.original_wg_config_path = admin_api.WG_CONFIG_PATH
        self.original_wg_interface = admin_api.WG_INTERFACE
        self.original_adblock_config_path = admin_api.ADBLOCK_CONFIG_PATH
        self.original_adblock_hosts_path = admin_api.ADBLOCK_HOSTS_PATH
        self.original_adblock_state_path = admin_api.ADBLOCK_STATE_PATH
        self.original_maintenance_state_path = admin_api.MAINTENANCE_STATE_PATH
        self.original_dns_query_log_path = admin_api.DNS_QUERY_LOG_PATH
        self.original_dns_query_log_config_path = admin_api.DNS_QUERY_LOG_CONFIG_PATH
        self.original_openvpn_status_path = admin_api.OPENVPN_STATUS_PATH
        admin_api.DB_PATH = Path(self.temp_dir.name) / "admins.sqlite3"
        admin_api.STATUS_PATH = Path(self.temp_dir.name) / "status.json"
        admin_api.WG_CONFIG_PATH = Path(self.temp_dir.name) / "wg0.conf"
        admin_api.WG_INTERFACE = "wg0"
        admin_api.ADBLOCK_CONFIG_PATH = Path(self.temp_dir.name) / "dnsmasq.d" / "adblock.conf"
        admin_api.ADBLOCK_HOSTS_PATH = Path(self.temp_dir.name) / "ads.hosts"
        admin_api.ADBLOCK_STATE_PATH = Path(self.temp_dir.name) / "adblock.json"
        admin_api.MAINTENANCE_STATE_PATH = Path(self.temp_dir.name) / "maintenance.json"
        admin_api.DNS_QUERY_LOG_PATH = Path(self.temp_dir.name) / "dns-queries.log"
        admin_api.DNS_QUERY_LOG_CONFIG_PATH = Path(self.temp_dir.name) / "dns-logging.conf"
        admin_api.OPENVPN_STATUS_PATH = Path(self.temp_dir.name) / "openvpn-status.log"
        admin_api.ADBLOCK_HOSTS_PATH.write_text("", encoding="utf-8")
        admin_api.WG_CONFIG_PATH.write_text("[Interface]\nAddress = 10.42.0.1/24\n", encoding="utf-8")
        admin_api.STATUS_PATH.write_text('{"protocols":{"services":{}}}', encoding="utf-8")
        admin_api.login_attempts.clear()
        admin_api.init_database()
        admin_api.bootstrap_admin("saeka", "temporary-passphrase")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), admin_api.AdminHandler)
        self.server.daemon_threads = True
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.address = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)
        admin_api.DB_PATH = self.original_db_path
        admin_api.STATUS_PATH = self.original_status_path
        admin_api.WG_CONFIG_PATH = self.original_wg_config_path
        admin_api.WG_INTERFACE = self.original_wg_interface
        admin_api.ADBLOCK_CONFIG_PATH = self.original_adblock_config_path
        admin_api.ADBLOCK_HOSTS_PATH = self.original_adblock_hosts_path
        admin_api.ADBLOCK_STATE_PATH = self.original_adblock_state_path
        admin_api.MAINTENANCE_STATE_PATH = self.original_maintenance_state_path
        admin_api.DNS_QUERY_LOG_PATH = self.original_dns_query_log_path
        admin_api.DNS_QUERY_LOG_CONFIG_PATH = self.original_dns_query_log_config_path
        admin_api.OPENVPN_STATUS_PATH = self.original_openvpn_status_path
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None, cookie=None, csrf=None, origin=None):
        connection = http.client.HTTPConnection(*self.address, timeout=5)
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload)
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        if origin:
            headers["Origin"] = origin
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        if response.getheader("Content-Type", "").startswith("application/json"):
            data = json.loads(response_body)
        else:
            data = response_body.decode("utf-8")
        set_cookie = response.getheader("Set-Cookie", "").split(";", 1)[0]
        status = response.status
        connection.close()
        return status, data, set_cookie

    def sign_in(self, username="saeka", password="temporary-passphrase"):
        status, data, set_cookie = self.request("POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return data, set_cookie

    def test_client_duration_uses_seconds_and_rejects_invalid_values(self):
        self.assertEqual(admin_api.parse_client_duration({"durationSeconds": 604800}), 604800)
        self.assertEqual(admin_api.parse_client_duration({"durationDays": 7}), 604800)
        self.assertEqual(admin_api.parse_client_duration({"durationSeconds": 0}), 0)
        for payload in (
            {"durationSeconds": -1},
            {"durationSeconds": "1.5"},
            {"durationSeconds": True},
            {"durationSeconds": 31536001},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                admin_api.parse_client_duration(payload)

    def test_adblock_profiles_and_custom_domains_are_validated_and_persisted(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)

        with patch.object(
            admin_api.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run:
            status, data, _ = self.request(
                "POST",
                "/api/adblock",
                {
                    "enabled": True,
                    "level": "strict",
                    "blockedDomains": [" Ads.Example.com ", "ads.example.com", "tracking.example.net"],
                },
                cookie=cookie,
                csrf=session["csrfToken"],
            )
            self.assertEqual(status, 200)
            self.assertEqual(data["adblock"]["level"], "strict")
            self.assertEqual(
                data["adblock"]["blockedDomains"],
                ["ads.example.com", "tracking.example.net"],
            )
            self.assertIn(
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
                data["adblock"]["sourceUrl"],
            )
            self.assertEqual(
                json.loads(admin_api.ADBLOCK_STATE_PATH.read_text(encoding="utf-8"))["blocked_domains"],
                ["ads.example.com", "tracking.example.net"],
            )
            self.assertTrue(
                any(call.args[0] == ["systemctl", "start", "--no-block", "vpn-adblock-update.service"] for call in run.call_args_list)
            )

            status, data, _ = self.request(
                "POST",
                "/api/adblock",
                {"enabled": True, "level": "unknown", "blockedDomains": ["not a domain"]},
                cookie=cookie,
                csrf=session["csrfToken"],
            )
            self.assertEqual(status, 400)
            self.assertIn("valid ad-blocking level", data["error"])
            self.assertEqual(run.call_count, 3)

            status, data, _ = self.request(
                "POST",
                "/api/adblock",
                {"enabled": True, "level": "strict", "blockedDomains": ["not a domain"]},
                cookie=cookie,
                csrf=session["csrfToken"],
            )
            self.assertEqual(status, 400)
            self.assertIn("Invalid blocked domain", data["error"])
            self.assertEqual(run.call_count, 3)

    def test_maintenance_notice_is_admin_managed_and_publicly_visible_on_portal(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)

        with patch.object(admin_api, "set_vpn_forwarding_block") as firewall:
            status, data, _ = self.request(
                "POST",
                "/api/maintenance",
                {"enabled": True, "message": "Planned network maintenance.", "blockInternet": True},
                cookie=cookie,
                csrf=session["csrfToken"],
            )
            firewall.assert_called_once_with(True)
        self.assertEqual(status, 200)
        self.assertEqual(
            data["maintenance"],
            {"enabled": True, "message": "Planned network maintenance.", "blockInternet": True},
        )

        with patch.object(
            admin_api,
            "set_vpn_forwarding_block",
            side_effect=[RuntimeError("firewall unavailable"), None],
        ) as firewall:
            with self.assertRaisesRegex(RuntimeError, "firewall unavailable"):
                admin_api.set_maintenance_state(False, "", False)
            self.assertEqual(firewall.call_count, 2)
        self.assertEqual(
            admin_api.read_maintenance_state(),
            {"enabled": True, "message": "Planned network maintenance.", "blockInternet": True},
        )

        status, data, _ = self.request("GET", "/api/portal/session")
        self.assertEqual(status, 200)
        self.assertEqual(
            data["maintenance"],
            {"enabled": True, "message": "Planned network maintenance.", "blockInternet": True},
        )

        status, data, _ = self.request(
            "POST",
            "/api/maintenance",
            {"enabled": True, "message": "x" * 501},
            cookie=cookie,
            csrf=session["csrfToken"],
        )
        self.assertEqual(status, 400)

        status, data, _ = self.request(
            "POST",
            "/api/maintenance",
            {"enabled": False, "message": "", "blockInternet": True},
            cookie=cookie,
            csrf=session["csrfToken"],
        )
        self.assertEqual(status, 400)
        self.assertIn("Enable the client maintenance notice", data["error"])

        status, data, _ = self.request(
            "POST",
            "/api/maintenance",
            {"enabled": False, "message": ""},
            cookie=cookie,
        )
        self.assertEqual(status, 403)

    def test_vpn_forwarding_pause_calls_installed_helper_and_reports_failure(self):
        with patch.object(
            admin_api.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run:
            admin_api.set_vpn_forwarding_block(True)
            run.assert_called_once_with(
                [admin_api.MAINTENANCE_FIREWALL_COMMAND, "enable"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

        with patch.object(
            admin_api.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "", "iptables failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "maintenance firewall"):
                admin_api.set_vpn_forwarding_block(False)

    def test_dns_query_logging_is_opt_in_and_attributes_queries_to_vpn_client(self):
        now = int(time.time())
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol) "
                "VALUES (?, ?, ?, ?, ?, ?, 'wireguard')",
                ("dns-client", "field-laptop", "dns-public", "private", "10.42.0.8/32", now),
            )
        admin_api.DNS_QUERY_LOG_PATH.write_text(
            "Sep 27 16:00:00 dnsmasq[123]: 1234 10.42.0.8/51342 query[A] ads.example.com from 10.42.0.8\n"
            "Sep 27 16:00:01 dnsmasq[123]: 1235 10.42.0.8/51342 query[AAAA] video.example.net from 10.42.0.8\n",
            encoding="utf-8",
        )
        admin_api.OPENVPN_STATUS_PATH.write_text(
            "ROUTING_TABLE,10.8.0.4,openvpn-laptop,198.51.100.9:51820,0\n",
            encoding="utf-8",
        )
        with admin_api.DNS_QUERY_LOG_PATH.open("a", encoding="utf-8") as query_log:
            query_log.write(
                "Sep 27 16:00:02 dnsmasq[123]: 1236 10.8.0.4/51342 query[A] media.example.org from 10.8.0.4\n"
            )
        queries = admin_api.read_dns_queries()
        self.assertEqual(len(queries), 3)
        self.assertEqual(queries[0]["client"], "openvpn-laptop")
        self.assertEqual(queries[0]["clientIp"], "10.8.0.4")
        self.assertEqual(queries[0]["domain"], "media.example.org")
        self.assertEqual(queries[1]["client"], "field-laptop")
        self.assertFalse(admin_api.dns_query_logging_enabled())

        with patch.object(
            admin_api.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run:
            self.assertTrue(admin_api.set_dns_query_logging(True))
            self.assertTrue(admin_api.dns_query_logging_enabled())
            self.assertIn("log-queries=extra", admin_api.DNS_QUERY_LOG_CONFIG_PATH.read_text(encoding="utf-8"))
            self.assertFalse(admin_api.set_dns_query_logging(False))
            self.assertFalse(admin_api.dns_query_logging_enabled())
            self.assertEqual(run.call_count, 4)

        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)
        status, _, _ = self.request("GET", "/api/telemetry/dns")
        self.assertEqual(status, 401)
        status, response, _ = self.request("GET", "/api/telemetry/dns", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(response["queries"][0]["client"], "openvpn-laptop")
        status, _, _ = self.request(
            "POST", "/api/telemetry/dns", {"enabled": True}, cookie=cookie
        )
        self.assertEqual(status, 403)
        with patch.object(
            admin_api.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ):
            status, response, _ = self.request(
                "POST",
                "/api/telemetry/dns",
                {"enabled": True},
                cookie=cookie,
                csrf=session["csrfToken"],
            )
        self.assertEqual(status, 200)
        self.assertTrue(response["enabled"])
        status, portal_session, _ = self.request("GET", "/api/portal/session")
        self.assertEqual(status, 200)
        self.assertTrue(portal_session["dnsLoggingEnabled"])

    def test_active_connections_separate_public_endpoint_from_assigned_vpn_ip(self):
        now = int(time.time())
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol) "
                "VALUES (?, ?, ?, ?, ?, ?, 'wireguard')",
                ("connection-client", "remote-user", "peer-public", "private", "10.42.0.9/32", now),
            )
        admin_api.OPENVPN_STATUS_PATH.write_text(
            "ROUTING_TABLE,10.8.0.6,openvpn-user,203.0.113.20:53321,0\n",
            encoding="utf-8",
        )

        def mock_command(arguments, **kwargs):
            if arguments == ["wg", "show", "wg0", "dump"]:
                dump = (
                    "wg0\tserver-public\t51820\toff\n"
                    f"peer-public\t(none)\t198.51.100.44:51234\t10.42.0.9/32\t{now}\t100\t200\toff\n"
                )
                return subprocess.CompletedProcess(arguments, 0, dump, "")
            if arguments == ["who"]:
                return subprocess.CompletedProcess(arguments, 0, "", "")
            self.fail(f"Unexpected command: {arguments}")

        with patch.object(admin_api.subprocess, "run", side_effect=mock_command):
            connections = admin_api.read_connections()
        wireguard = next(item for item in connections if item["proto"] == "wireguard")
        self.assertEqual(wireguard["user"], "remote-user")
        self.assertEqual(wireguard["ip"], "198.51.100.44")
        self.assertEqual(wireguard["tunnelIp"], "10.42.0.9")
        self.assertEqual(wireguard["remoteEndpoint"], "198.51.100.44:51234")
        openvpn = next(item for item in connections if item["proto"] == "openvpn")
        self.assertEqual(openvpn["user"], "openvpn-user")
        self.assertEqual(openvpn["ip"], "203.0.113.20")
        self.assertEqual(openvpn["tunnelIp"], "10.8.0.6")

    def test_vpn_endpoint_helpers_format_ipv6_authorities(self):
        with patch.dict(os.environ, {"DOMAIN": "2001:db8::10", "WG_PORT": "51820"}):
            self.assertEqual(admin_api._wireguard_endpoint(), "[2001:db8::10]:51820")
            self.assertEqual(admin_api._vpn_host(), "2001:db8::10")
            self.assertEqual(admin_api._client_endpoint("wireguard"), "[2001:db8::10]:51820")
            self.assertTrue(
                admin_api.build_share_uri("ssh", "alice", "a-secret", "2001:db8::10")
                .startswith("ssh://alice:a-secret@[2001:db8::10]:22")
            )

    def test_client_creation_rejects_bad_protocol_and_weak_password_before_provisioning(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)
        with patch.object(admin_api, "create_wireguard_client") as provision:
            for payload in (
                {"username": "field-device", "protocol": "unknown"},
                {"username": "field-device", "password": "short"},
                {"username": "field-device", "routeMode": "unrestricted"},
            ):
                status, data, _ = self.request(
                    "POST", "/api/clients", payload, cookie=cookie, csrf=session["csrfToken"]
                )
                self.assertEqual(status, 400)
                self.assertIn("error", data)
            provision.assert_not_called()

    def test_status_requires_authentication(self):
        status, data, _ = self.request("GET", "/api/status")
        self.assertEqual(status, 401)
        self.assertIn("error", data)

    def test_existing_admin_bootstrap_does_not_need_or_reset_a_secret(self):
        environment = os.environ.copy()
        environment["VPN_ADMIN_DB"] = str(admin_api.DB_PATH)
        environment.pop("VPN_ADMIN_INITIAL_PASSWORD", None)
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--init-admin"],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("existing accounts were preserved", result.stdout)

    def test_bootstrap_login_forces_password_rotation_and_csrf(self):
        with admin_api.database() as connection:
            row = connection.execute("SELECT salt, password_hash FROM admins WHERE username = ?", ("saeka",)).fetchone()
        self.assertNotEqual(row["password_hash"], b"temporary-passphrase")
        self.assertEqual(len(row["salt"]), 16)

        login, cookie = self.sign_in()
        self.assertTrue(login["mustChangePassword"])
        status, _, _ = self.request("GET", "/api/status", cookie=cookie)
        self.assertEqual(status, 428)

        status, data, rotated_cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        self.assertEqual(status, 200)
        self.assertTrue(rotated_cookie.startswith("vpn_session="))
        self.assertFalse(data["mustChangePassword"])
        status, session, _ = self.request("GET", "/api/session", cookie=rotated_cookie)
        self.assertEqual(status, 200)
        self.assertFalse(session["mustChangePassword"])
        status, _, _ = self.request("GET", "/api/status", cookie=rotated_cookie)
        self.assertEqual(status, 200)

    def test_admin_user_lifecycle_requires_csrf_and_protects_last_account(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)
        csrf = session["csrfToken"]

        status, _, _ = self.request("POST", "/api/users", {"username": "operator", "password": "another-long-secure-passphrase"}, cookie=cookie)
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/users", {"username": "operator", "password": "another-long-secure-passphrase"}, cookie=cookie, csrf=csrf)
        self.assertEqual(status, 201)
        added_user = admin_api.verify_password("operator", "another-long-secure-passphrase")
        self.assertTrue(added_user["must_change_password"])
        status, users, _ = self.request("GET", "/api/users", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual({user["username"] for user in users["users"]}, {"saeka", "operator"})

        status, _, _ = self.request("DELETE", "/api/users/operator", cookie=cookie, csrf=csrf)
        self.assertEqual(status, 200)
        status, data, _ = self.request("DELETE", "/api/users/saeka", cookie=cookie, csrf=csrf)
        self.assertEqual(status, 400)
        self.assertIn("cannot remove", data["error"])

    def test_wireguard_listing_and_expiry_ignore_other_protocols(self):
        now = int(time.time())
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, protocol) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "other-client",
                    "other-client",
                    "openvpn:key",
                    "openvpn:key",
                    "openvpn:other-client",
                    now - 10,
                    now - 1,
                    "openvpn",
                ),
            )

        with patch.object(admin_api, "revoke_wireguard_client") as revoke, patch.object(
            admin_api, "_wireguard_peer_metrics", return_value={}
        ):
            self.assertEqual(admin_api.list_wireguard_clients(now), [])
            revoke.assert_not_called()

        with admin_api.database() as connection:
            row = connection.execute(
                "SELECT protocol FROM vpn_clients WHERE id = ?", ("other-client",)
            ).fetchone()
        self.assertEqual(row["protocol"], "openvpn")

    def test_xray_xhttp_shares_use_the_configured_inbound_path(self):
        now = int(time.time())
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "xray-client",
                    "xray-client",
                    "xray:xray-client",
                    "xray:xray-client",
                    "xray:xray-client",
                    now,
                    "xray",
                    json.dumps({"uuid": "00000000-0000-4000-8000-000000000001"}),
                ),
            )

        with patch.dict(os.environ, {"DOMAIN": "vpn.example.test"}):
            transports = admin_api.xray_transports("test-uuid")
            _, account_share = admin_api.get_xray_client_share("xray-client")
            account_transports = admin_api.get_xray_client_transports("xray-client")

        xhttp = next(item for item in transports if item["id"] == "vless-xhttp")
        self.assertEqual(
            {item["id"] for item in transports},
            {
                "vless-xhttp",
                "vless-ws",
                "vless-grpc",
                "vless-tcp",
                "vmess-ws",
                "trojan-ws",
            },
        )
        self.assertEqual(xhttp["path"], "/saeka-vless-xh")
        self.assertIn("path=%2Fsaeka-vless-xh", xhttp["share"])
        self.assertIn("path=%2Fsaeka-vless-xh", account_share)
        self.assertIn(
            "00000000-0000-4000-8000-000000000001@vpn.example.test",
            next(item for item in account_transports if item["id"] == "vless-xhttp")["share"],
        )

        generic_vless_share = admin_api.build_share_uri(
            "xray", "xray-client", "", "vpn.example.test"
        )
        self.assertIn(
            "00000000-0000-4000-8000-000000000001@vpn.example.test",
            generic_vless_share,
        )
        self.assertIn("path=%2Fsaeka-vless-xh", generic_vless_share)
        self.assertTrue(
            admin_api.build_share_uri(
                "vmess", "xray-client", "", "vpn.example.test"
            ).startswith("vmess://")
        )
        self.assertTrue(
            admin_api.build_share_uri(
                "trojan", "xray-client", "", "vpn.example.test"
            ).startswith("trojan://")
        )

    def test_xray_revocation_removes_vless_vmess_and_trojan_credentials(self):
        client_uuid = "00000000-0000-4000-8000-000000000001"
        config_path = Path(self.temp_dir.name) / "xray.json"
        config_path.write_text(json.dumps({
            "inbounds": [
                {"protocol": "vless", "settings": {"clients": [{"id": client_uuid}, {"id": "keep-vless"}]}},
                {"protocol": "vmess", "settings": {"clients": [{"id": client_uuid}, {"id": "keep-vmess"}]}},
                {"protocol": "trojan", "settings": {"clients": [{"password": client_uuid}, {"password": "keep-trojan"}]}},
            ]
        }), encoding="utf-8")
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "xray-revoke",
                    "xray-revoke",
                    "xray:xray-revoke",
                    "xray:xray-revoke",
                    "xray:xray-revoke",
                    int(time.time()),
                    "xray",
                    json.dumps({"uuid": client_uuid}),
                ),
            )

        with patch.object(admin_api, "XRAY_CONFIG_PATH", config_path), patch.object(
            admin_api.subprocess, "run"
        ):
            admin_api.revoke_xray_client("xray-revoke")

        inbounds = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"]
        for inbound in inbounds:
            key = "password" if inbound["protocol"] == "trojan" else "id"
            self.assertNotIn(client_uuid, [client[key] for client in inbound["settings"]["clients"]])

    def test_expired_non_wireguard_account_uses_protocol_revoker(self):
        now = int(time.time())
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, protocol) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("expired-ssh", "expired-ssh", "ssh:key", "ssh:key", "ssh:key", now - 100, now - 1, "ssh"),
            )

        with patch.object(admin_api, "revoke_ssh_client") as revoke:
            admin_api.expire_non_wireguard_clients(now)

        revoke.assert_called_once_with("expired-ssh")

    def test_all_protocol_client_listing_reports_portal_login_state(self):
        now = int(time.time())
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol, password_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("ssh-client", "ssh-client", "ssh:key", "ssh:key", "ssh:key", now, "ssh", b"hashed-password"),
            )

        with patch.object(admin_api, "list_wireguard_clients", return_value=[]):
            client = admin_api.list_all_clients()[0]

        self.assertTrue(client["portalReady"])
        self.assertNotIn("password_hash", client)

    def test_ipsec_export_contains_current_eap_credentials(self):
        now = int(time.time())
        secrets_path = Path(self.temp_dir.name) / "ipsec.secrets"
        secrets_path.write_text('ike-user : EAP "ike-secret-value"\n', encoding="utf-8")
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("ipsec-client", "ike-user", "ipsec:key", "ipsec:key", "ipsec:key", now, "ipsec"),
            )

        with patch.object(admin_api, "IPSEC_SECRETS", secrets_path), patch.dict(
            os.environ, {"DOMAIN": "vpn.example.test"}
        ):
            username, config = admin_api.get_ipsec_client_info("ipsec-client")

        self.assertEqual(username, "ike-user")
        self.assertIn("Password: ike-secret-value", config)
        self.assertEqual(
            admin_api.get_config_meta("ipsec")[:2],
            ("txt", "text/plain; charset=utf-8"),
        )

    def test_openvpn_revocation_installs_generated_crl(self):
        now = int(time.time())
        easy_rsa = Path(self.temp_dir.name) / "easy-rsa"
        crl_source = easy_rsa / "pki" / "crl.pem"
        crl_source.parent.mkdir(parents=True)
        crl_source.write_text("revoked certificate list\n", encoding="utf-8")
        crl_target = Path(self.temp_dir.name) / "server" / "crl.pem"
        with admin_api.database() as connection:
            connection.execute(
                "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, protocol) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("openvpn-client", "ovpn-user", "ovpn:key", "ovpn:key", "ovpn:key", now, "openvpn"),
            )

        completed = admin_api.subprocess.CompletedProcess([], 0, "", "")
        with patch.object(admin_api, "EASYRSA_DIR", easy_rsa), patch.object(
            admin_api, "OPENVPN_CRL_PATH", crl_target
        ), patch.object(admin_api.subprocess, "run", return_value=completed):
            admin_api.revoke_openvpn_client("openvpn-client")

        self.assertEqual(crl_target.read_text(encoding="utf-8"), "revoked certificate list\n")
        with admin_api.database() as connection:
            self.assertIsNone(
                connection.execute("SELECT id FROM vpn_clients WHERE id = ?", ("openvpn-client",)).fetchone()
            )

    def test_wireguard_client_lifecycle_requires_csrf_and_provisions_config(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)
        csrf = session["csrfToken"]
        now = int(time.time())
        existing_peer = f"existing-public\t(none)\t203.0.113.9:51820\t10.42.0.2/32\t{now}\t0\t0\toff"
        client_installed = False

        def mock_wg(command, **kwargs):
            nonlocal client_installed
            arguments = command[1:]
            if arguments == ["show", "wg0", "dump"]:
                peers = existing_peer
                if client_installed:
                    peers += f"\nclient-public\t(none)\t203.0.113.10:51820\t10.42.0.3/32\t{now}\t12500\t8300\toff"
                return subprocess.CompletedProcess(command, 0, f"wg0\tserver-public\t51820\toff\n{peers}\n", "")
            if arguments == ["show", "wg0", "public-key"]:
                return subprocess.CompletedProcess(command, 0, "server-public\n", "")
            if arguments == ["genkey"]:
                return subprocess.CompletedProcess(command, 0, "client-private\n", "")
            if arguments == ["pubkey"]:
                self.assertEqual(kwargs["input"], "client-private\n")
                return subprocess.CompletedProcess(command, 0, "client-public\n", "")
            if arguments[:3] == ["set", "wg0", "peer"]:
                client_installed = arguments[-1] != "remove"
                return subprocess.CompletedProcess(command, 0, "", "")
            self.fail(f"Unexpected WireGuard command: {arguments}")

        with patch.dict(os.environ, {"DOMAIN": "vpn.example.test", "WG_PORT": "51820"}), patch.object(
            admin_api.subprocess, "run", side_effect=mock_wg
        ):
            status, _, _ = self.request(
                "POST", "/api/clients", {"username": "field-laptop", "durationDays": 7}, cookie=cookie
            )
            self.assertEqual(status, 403)

            status, created, _ = self.request(
                "POST",
                "/api/clients",
                {"username": " field-laptop ", "durationDays": 7, "routeMode": "split"},
                cookie=cookie,
                csrf=csrf,
            )
            self.assertEqual(status, 201)
            self.assertEqual(created["client"]["address"], "10.42.0.3")
            self.assertEqual(created["client"]["username"], "field-laptop")
            self.assertEqual(created["client"]["protocol"], "wireguard")
            self.assertEqual(created["client"]["routeMode"], "split")
            self.assertTrue(created["client"]["temporaryPassword"])
            self.assertIn("PrivateKey = client-private", created["config"])
            self.assertIn("Endpoint = vpn.example.test:51820", created["config"])
            self.assertIn("DNS = 10.42.0.1", created["config"])
            self.assertIn("PublicKey = server-public", created["config"])
            self.assertIn("AllowedIPs = 10.42.0.0/24", created["config"])
            self.assertIn("PublicKey = client-public", admin_api.WG_CONFIG_PATH.read_text(encoding="utf-8"))

            status, clients, _ = self.request("GET", "/api/clients", cookie=cookie)
            self.assertEqual(status, 200)
            self.assertEqual(len(clients["clients"]), 1)
            self.assertEqual(clients["clients"][0]["status"], "connected")
            self.assertNotIn("private_key", clients["clients"][0])
            self.assertEqual(clients["clients"][0]["durationDays"], 7)
            self.assertEqual(clients["clients"][0]["routeMode"], "split")
            self.assertEqual(clients["clients"][0]["bytesReceived"], 12500)
            self.assertEqual(clients["clients"][0]["bytesSent"], 8300)
            status, downloaded_config, _ = self.request(
                "GET", f"/api/clients/{created['client']['id']}/config", cookie=cookie
            )
            self.assertEqual(status, 200)
            self.assertIn("AllowedIPs = 10.42.0.0/24", downloaded_config)

            status, portal_login, client_cookie = self.request(
                "POST",
                "/api/portal/login",
                {"username": "field-laptop", "password": created["client"]["temporaryPassword"]},
            )
            self.assertEqual(status, 200)
            self.assertTrue(portal_login["mustChangePassword"])
            status, _, _ = self.request("GET", "/api/portal/account", cookie=client_cookie)
            self.assertEqual(status, 428)
            status, password_result, client_cookie = self.request(
                "POST",
                "/api/portal/password",
                {"oldPassword": created["client"]["temporaryPassword"], "newPassword": "client-secure-passphrase-43"},
                cookie=client_cookie,
                csrf=portal_login["csrfToken"],
            )
            self.assertEqual(status, 200)
            self.assertFalse(password_result["mustChangePassword"])
            status, account, _ = self.request("GET", "/api/portal/account", cookie=client_cookie)
            self.assertEqual(status, 200)
            self.assertEqual(account["account"]["address"], "10.42.0.3")
            self.assertEqual(account["account"]["status"], "connected")
            self.assertEqual(account["account"]["bytesReceived"], 12500)
            status, portal_config, _ = self.request("GET", "/api/portal/config", cookie=client_cookie)
            self.assertEqual(status, 200)
            self.assertIn("PrivateKey = client-private", portal_config)
            status, _, _ = self.request("GET", "/api/clients", cookie=client_cookie)
            self.assertEqual(status, 401)

            client_id = created["client"]["id"]
            status, config, _ = self.request("GET", f"/api/clients/{client_id}/config", cookie=cookie)
            self.assertEqual(status, 200)
            self.assertIn("PrivateKey = client-private", config)
            self.assertIn("DNS = 10.42.0.1", config)

            with admin_api.database() as connection:
                connection.execute("UPDATE vpn_clients SET expires_at = ? WHERE id = ?", (int(time.time()) - 1, client_id))
            status, data, _ = self.request("GET", f"/api/clients/{client_id}/config", cookie=cookie)
            self.assertEqual(status, 410)
            self.assertIn("expired", data["error"])
            with admin_api.database() as connection:
                connection.execute("UPDATE vpn_clients SET expires_at = ? WHERE id = ?", (created["client"]["expiresAt"], client_id))

            status, reset, _ = self.request(
                "POST", f"/api/clients/{client_id}/password", {}, cookie=cookie, csrf=csrf
            )
            self.assertEqual(status, 200)
            self.assertTrue(reset["temporaryPassword"])
            status, _, _ = self.request("GET", "/api/portal/account", cookie=client_cookie)
            self.assertEqual(status, 401)
            status, new_portal_login, _ = self.request(
                "POST",
                "/api/portal/login",
                {"username": "field-laptop", "password": reset["temporaryPassword"]},
            )
            self.assertEqual(status, 200)
            self.assertTrue(new_portal_login["mustChangePassword"])

            status, _, _ = self.request("DELETE", f"/api/clients/{client_id}", cookie=cookie)
            self.assertEqual(status, 403)
            status, _, _ = self.request("DELETE", f"/api/clients/{client_id}", cookie=cookie, csrf=csrf)
            self.assertEqual(status, 200)
            self.assertNotIn("PublicKey = client-public", admin_api.WG_CONFIG_PATH.read_text(encoding="utf-8"))
            with admin_api.database() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM vpn_clients").fetchone()[0], 0)

    def test_adblock_toggle_requires_admin_csrf_and_rolls_back_invalid_config(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)
        csrf = session["csrfToken"]

        status, _, _ = self.request("GET", "/api/adblock")
        self.assertEqual(status, 401)
        status, state, _ = self.request("GET", "/api/adblock", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertFalse(state["adblock"]["enabled"])

        def mock_commands(arguments, **kwargs):
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch.object(admin_api.subprocess, "run", side_effect=mock_commands):
            status, _, _ = self.request("POST", "/api/adblock", {"enabled": True}, cookie=cookie)
            self.assertEqual(status, 403)
            status, response, _ = self.request(
                "POST", "/api/adblock", {"enabled": True}, cookie=cookie, csrf=csrf
            )
            self.assertEqual(status, 200)
            self.assertTrue(response["adblock"]["enabled"])
            self.assertEqual(
                admin_api.ADBLOCK_CONFIG_PATH.read_text(encoding="utf-8"),
                "conf-file=/var/lib/vpnfront/adblock-dnsmasq.conf\n",
            )

            admin_api.ADBLOCK_CONFIG_PATH.write_text(
                f"addn-hosts={admin_api.ADBLOCK_HOSTS_PATH}\n", encoding="utf-8"
            )
            status, response, _ = self.request(
                "POST", "/api/adblock", {"enabled": True}, cookie=cookie, csrf=csrf
            )
            self.assertEqual(status, 200)
            self.assertTrue(response["adblock"]["enabled"])
            self.assertEqual(
                admin_api.ADBLOCK_CONFIG_PATH.read_text(encoding="utf-8"),
                "conf-file=/var/lib/vpnfront/adblock-dnsmasq.conf\n",
            )

            def reject_config(arguments, **kwargs):
                status_code = 1 if arguments == ["dnsmasq", "--test"] else 0
                return subprocess.CompletedProcess(arguments, status_code, "", "invalid config")

            with patch.object(admin_api.subprocess, "run", side_effect=reject_config):
                status, data, _ = self.request(
                    "POST", "/api/adblock", {"enabled": False}, cookie=cookie, csrf=csrf
                )
                self.assertEqual(status, 503)
                self.assertIn("rejected", data["error"])
            self.assertTrue(admin_api.ADBLOCK_CONFIG_PATH.exists())
            self.assertTrue(admin_api.read_adblock_state()["enabled"])

            status, response, _ = self.request(
                "POST", "/api/adblock", {"enabled": False}, cookie=cookie, csrf=csrf
            )
            self.assertEqual(status, 200)
            self.assertFalse(response["adblock"]["enabled"])
            self.assertFalse(admin_api.ADBLOCK_CONFIG_PATH.exists())

    def test_cross_origin_logout_is_rejected(self):
        login, cookie = self.sign_in()
        status, data, _ = self.request(
            "POST",
            "/api/logout",
            {},
            cookie=cookie,
            csrf=login["csrfToken"],
            origin="https://attacker.invalid",
        )
        self.assertEqual(status, 403)
        self.assertIn("Cross-origin", data["error"])

    def test_service_restart_is_allowlisted(self):
        login, cookie = self.sign_in()
        _, _, cookie = self.request(
            "POST",
            "/api/password",
            {"oldPassword": "temporary-passphrase", "newPassword": "longer-secure-passphrase-42"},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        _, session, _ = self.request("GET", "/api/session", cookie=cookie)
        headers = {"csrf": session["csrfToken"]}
        def mock_systemctl(args, **kwargs):
            if args[:3] == ["systemctl", "list-unit-files", "--type=service"]:
                return admin_api.subprocess.CompletedProcess(args, 0, "nginx.service enabled\n", "")
            return admin_api.subprocess.CompletedProcess(args, 0, "", "")

        with patch.object(admin_api.subprocess, "run", side_effect=mock_systemctl) as run:
            status, _, _ = self.request("POST", "/api/services/not-real/restart", {}, cookie=cookie, **headers)
            self.assertEqual(status, 404)
            run.assert_not_called()

            status, data, _ = self.request("POST", "/api/services/nginx/restart", {}, cookie=cookie, **headers)
            self.assertEqual(status, 200)
            self.assertEqual(data["service"], "nginx")
            self.assertEqual(run.call_args_list[1].args[0], ["systemctl", "restart", "nginx"])
            self.assertEqual(run.call_args_list[2].args[0], ["systemctl", "start", "vpn-status-refresh.service"])

    def test_openvpn_restart_resolves_template_unit(self):
        result = admin_api.subprocess.CompletedProcess(
            ["systemctl"],
            0,
            "openvpn-server@.service enabled\n",
            "",
        )
        with patch.object(admin_api.subprocess, "run", return_value=result):
            self.assertEqual(admin_api.resolve_service_unit("openvpn"), "openvpn-server@server.service")


if __name__ == "__main__":
    unittest.main()