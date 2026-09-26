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
        admin_api.DB_PATH = Path(self.temp_dir.name) / "admins.sqlite3"
        admin_api.STATUS_PATH = Path(self.temp_dir.name) / "status.json"
        admin_api.WG_CONFIG_PATH = Path(self.temp_dir.name) / "wg0.conf"
        admin_api.WG_INTERFACE = "wg0"
        admin_api.ADBLOCK_CONFIG_PATH = Path(self.temp_dir.name) / "dnsmasq.d" / "adblock.conf"
        admin_api.ADBLOCK_HOSTS_PATH = Path(self.temp_dir.name) / "ads.hosts"
        admin_api.ADBLOCK_STATE_PATH = Path(self.temp_dir.name) / "adblock.json"
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
                {"username": "field-laptop", "durationDays": 7},
                cookie=cookie,
                csrf=csrf,
            )
            self.assertEqual(status, 201)
            self.assertEqual(created["client"]["address"], "10.42.0.3")
            self.assertEqual(created["client"]["username"], "field-laptop")
            self.assertTrue(created["client"]["temporaryPassword"])
            self.assertIn("PrivateKey = client-private", created["config"])
            self.assertIn("Endpoint = vpn.example.test:51820", created["config"])
            self.assertIn("DNS = 10.42.0.1", created["config"])
            self.assertIn("PublicKey = server-public", created["config"])
            self.assertIn("AllowedIPs = 0.0.0.0/0", created["config"])
            self.assertIn("PublicKey = client-public", admin_api.WG_CONFIG_PATH.read_text(encoding="utf-8"))

            status, clients, _ = self.request("GET", "/api/clients", cookie=cookie)
            self.assertEqual(status, 200)
            self.assertEqual(len(clients["clients"]), 1)
            self.assertEqual(clients["clients"][0]["status"], "connected")
            self.assertNotIn("private_key", clients["clients"][0])
            self.assertEqual(clients["clients"][0]["durationDays"], 7)
            self.assertEqual(clients["clients"][0]["bytesReceived"], 12500)
            self.assertEqual(clients["clients"][0]["bytesSent"], 8300)

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
                f"addn-hosts={admin_api.ADBLOCK_HOSTS_PATH}\n",
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