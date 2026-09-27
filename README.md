# VPS VPN Control Stack

## Installation

Run `setup-vpn-stack.sh` on the target Debian VPS. Pass `--domain vpn.example.com` for a domain-based endpoint; when omitted, the installer detects the VPS public IPv4. IP-based installs use a self-signed certificate, so browsers will require an explicit trust decision. A domain pointed at the VPS is required for a publicly trusted Let's Encrypt certificate.

The installer configures WireGuard, OpenVPN, IKEv2/IPsec, the client portal, and the admin panel. Xray account provisioning requires an independently installed Xray service and `/usr/local/etc/xray/config.json`; this installer does not install the Xray core.

## Management

After installation, run `vpn-admin` for the interactive terminal menu. Commands include `status`, `protocols`, `cert`, `domain`, `webcheck`, `logs`, `restart`, and `adblock {status|on|off}`. Use `vpn-admin domain` for DNS and TLS setup guidance. The install command shown by the panel or terminal is for a fresh VPS; changing a production host is not currently an automated operation.

## Local Verification

Run `bash verify-vpn-stack.sh` to parse the source, run the isolated unit tests, and check repository wiring. It does not contact or inspect a VPS by default. Live host checks are explicitly opt-in with `RUN_HOST_CHECKS=1`.