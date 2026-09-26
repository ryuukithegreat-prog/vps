import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "vpn-status.py"
SPEC = importlib.util.spec_from_file_location("vpn_status", MODULE_PATH)
vpn_status = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vpn_status)


class StatusParserTests(unittest.TestCase):
    def test_wireguard_counts_recent_handshakes_only(self):
        output = """wg0 private public 51820 off
wg0 active-key (none) 198.51.100.4:50000 10.42.0.2/32 999 1024 2048 25
wg0 idle-key (none) (none) 10.42.0.3/32 0 0 0 0"""

        self.assertEqual(
            vpn_status.parse_wg_output(output, now=1000),
            {"active_clients": 1, "total_clients": 2},
        )

    def test_openvpn_v2_counts_client_rows_not_headers(self):
        output = """HEADER,CLIENT_LIST,Common Name,Real Address
CLIENT_LIST,alice,198.51.100.5:5000
CLIENT_LIST,bob,198.51.100.6:5000
HEADER,ROUTING_TABLE,Virtual Address,Common Name"""

        self.assertEqual(vpn_status.parse_openvpn_status(output), 2)

    def test_openvpn_v1_counts_only_rows_in_client_section(self):
        output = """OpenVPN CLIENT LIST
Common Name,Real Address,Bytes Received
alice,198.51.100.5:5000,123
ROUTING TABLE
Virtual Address,Common Name,Real Address
10.8.0.2,alice,198.51.100.5:5000
GLOBAL STATS
"""

        self.assertEqual(vpn_status.parse_openvpn_status(output), 1)

    def test_service_units_resolve_debian_templates(self):
        output = """nginx.service enabled
wg-quick@.service static
openvpn-server@.service enabled
strongswan-starter.service enabled"""
        with patch.object(vpn_status, "run", return_value=output):
            self.assertEqual(
                vpn_status.resolve_service_units(),
                {
                    "nginx": "nginx.service",
                    "wireguard": "wg-quick@wg0.service",
                    "openvpn": "openvpn-server@server.service",
                    "ipsec": "strongswan-starter.service",
                },
            )


if __name__ == "__main__":
    unittest.main()