import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "vpn-adblock-rules.py"
SPEC = importlib.util.spec_from_file_location("vpn_adblock_rules", MODULE_PATH)
rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rules)


class AdblockRuleTests(unittest.TestCase):
    def test_parses_abp_hosts_and_plain_domain_formats(self):
        domains = rules.parse_domains(
            [
                "! comments are ignored",
                "||ads.example.com^",
                "||tracker.example.net^$third-party",
                "@@||allowed.example.com^",
                "0.0.0.0 blocker.example.org www.blocker.example.org",
                "plain.example.edu",
                "||*.wildcard.example^",
                "localhost",
                "localhost.local",
                "not a domain",
            ]
        )
        self.assertEqual(
            domains,
            {
                "ads.example.com",
                "tracker.example.net",
                "blocker.example.org",
                "www.blocker.example.org",
                "plain.example.edu",
            },
        )

    def test_cli_emits_dnsmasq_suffix_rules(self):
        self.assertEqual(
            rules.render_rules(["||example.com^", "0.0.0.0 ads.example.net"]),
            ["address=/ads.example.net/0.0.0.0", "address=/example.com/0.0.0.0"],
        )


if __name__ == "__main__":
    unittest.main()