#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] Run this utility as root."
  exit 1
fi

if [[ -r /etc/vpnfront/.env ]]; then
  set -a
  source /etc/vpnfront/.env
  set +a
fi

MANAGED_SERVICES=(
  dnsmasq.service
  wg-quick@wg0.service
  openvpn-server@server.service
  openvpn-server@server-tcp.service
  strongswan-starter.service
  udpgw.service
  xray.service
  ws-ssh-bridge.service
  wstunnel.service
  vpn-admin-api.service
  nginx.service
  sslh.service
)

show_status() {
  echo "==== Service status ===="
  for unit in "${MANAGED_SERVICES[@]}"; do
    printf '%-36s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
  done
  echo "==== VPN, web, and tunnel listeners ===="
  ss -H -lntup | grep -E ':(22|53|80|443|500|4500|1194|51820|7300|10443|2087|2088|4443|8080|8081|8443|9998|1000[1-5]|1080|1081)([[:space:]]|$)' || true
  echo "==== Midnight restart timer ===="
  systemctl --no-pager status vpnfront-restart.timer --lines=8 || true
}

show_protocols() {
  echo "==== Protocol summary ===="
  /usr/local/bin/vpn-status-report || true
}

check_cert() {
  /usr/local/bin/vpn-cert-check "${DOMAIN:-vpn.example.com}" 443 || true
}

show_domain_guide() {
  local domain="${DOMAIN:-}"
  echo "==== Domain and TLS setup ===="
  if [[ -n "$domain" ]]; then
    printf 'Configured host: %s\n' "$domain"
    printf 'DNS A records:\n'
    getent ahostsv4 "$domain" | awk '!seen[$1]++ { print "  " $1 }' || true
    /usr/local/bin/vpn-cert-check "$domain" 443 || true
  else
    echo "No DOMAIN is present in /etc/vpnfront/.env."
  fi
  cat <<'GUIDE'

For a fresh Debian 12 VPS:
1. Point a DNS A record for your hostname to the VPS public IPv4.
2. Check the address on the VPS with: curl -4 https://api.ipify.org
3. Wait for DNS to resolve: getent ahostsv4 your.domain
4. Run the installer from its project directory:
   sudo ./setup-vpn-stack.sh --domain your.domain --email admin@your.domain

An IP-based install uses a self-signed certificate. A public domain that resolves
to this VPS is required for Let's Encrypt. Do not rerun the installer on a live
VPS just to change its host; domain migration needs coordinated service changes.
GUIDE
}

check_web_routes() {
  local domain="${DOMAIN:-}"
  if [[ -z "$domain" ]]; then
    echo "[ERROR] DOMAIN is not configured in /etc/vpnfront/.env."
    return 1
  fi
  printf 'Frontend: '
  curl --fail --silent --show-error --max-time 8 -o /dev/null -w '%{http_code}\n' "https://${domain}/"
  printf 'Admin: '
  curl --fail --silent --show-error --location --max-time 8 -o /dev/null -w '%{http_code}\n' "https://${domain}/admin/"
  printf 'API session: '
  curl --fail --silent --show-error --max-time 8 "https://${domain}/api/session" | jq -e 'type == "object" and .authenticated == false' >/dev/null
  echo "200 JSON unauthenticated response"
}

show_recent_logs() {
  journalctl --no-pager --since '1 hour ago' -n 120 \
    -u vpn-admin-api.service -u nginx.service -u sslh.service -u xray.service \
    -u ws-ssh-bridge.service -u wstunnel.service
}

show_adblock() {
  echo "==== VPN DNS ad blocking ===="
  if [[ -f /var/lib/vpnfront/adblock.json ]]; then
    jq . /var/lib/vpnfront/adblock.json
  else
    echo "Ad-block state is not initialized."
  fi
  systemctl --no-pager status dnsmasq vpn-adblock-update.timer --lines=8 || true
}

manage_maintenance_internet() {
  local choice="${1:-status}"
  local state=/var/lib/vpnfront/maintenance.json
  local temporary backup previous
  if [[ ! -f "$state" ]]; then
    echo "Maintenance state is not initialized."
    return 1
  fi
  case "$choice" in
    status)
      jq '{enabled, message, block_internet}' "$state"
      printf 'Forwarding firewall: '
      /usr/local/sbin/vpn-maintenance-firewall status
      ;;
    internet-on|internet-off)
      if [[ "$choice" == internet-on ]] && [[ "$(jq -r '.enabled // false' "$state")" != true ]]; then
        echo "Enable a client maintenance notice before pausing internet forwarding." >&2
        return 1
      fi
      previous="$(jq -r '.block_internet // false' "$state")"
      temporary="$(mktemp /var/lib/vpnfront/maintenance.XXXXXX)"
      backup="$(mktemp /var/lib/vpnfront/maintenance-backup.XXXXXX)"
      cp -p "$state" "$backup"
      jq --argjson paused "$([[ "$choice" == internet-on ]] && printf true || printf false)" \
        '.block_internet = $paused' "$state" >"$temporary"
      chmod 600 "$temporary"
      mv "$temporary" "$state"
      if ! /usr/local/sbin/vpn-maintenance-firewall "$([[ "$choice" == internet-on ]] && printf enable || printf disable)"; then
        mv "$backup" "$state"
        /usr/local/sbin/vpn-maintenance-firewall "$([[ "$previous" == true ]] && printf enable || printf disable)" || true
        echo "Could not apply maintenance firewall rules; previous state restored." >&2
        return 1
      fi
      rm -f "$backup"
      manage_maintenance_internet status
      ;;
    *)
      echo "Usage: $0 maintenance {status|internet-on|internet-off}" >&2
      return 2
      ;;
  esac
}

toggle_adblock() {
  local choice="${1:-}"
  local config=/etc/dnsmasq.d/vpnfront-adblock.conf
  local state=/var/lib/vpnfront/adblock.json
  local config_backup state_backup config_tmp state_tmp had_config=0 had_state=0
  config_backup="$(mktemp /etc/dnsmasq.d/vpnfront-adblock.backup.XXXXXX)"
  state_backup="$(mktemp /var/lib/vpnfront/adblock.backup.XXXXXX)"
  config_tmp="$(mktemp /etc/dnsmasq.d/vpnfront-adblock.tmp.XXXXXX)"
  state_tmp="$(mktemp /var/lib/vpnfront/adblock.tmp.XXXXXX)"
  if [[ -f "$config" ]]; then
    cp -p "$config" "$config_backup"
    had_config=1
  fi
  if [[ -f "$state" ]]; then
    cp -p "$state" "$state_backup"
    had_state=1
  fi

  case "$choice" in
    on)
      printf 'conf-file=/var/lib/vpnfront/adblock-dnsmasq.conf\n' >"$config_tmp"
      chmod 600 "$config_tmp"
      mv "$config_tmp" "$config"
      ;;
    off)
      rm -f "$config"
      ;;
    *)
      rm -f "$config_backup" "$state_backup" "$config_tmp" "$state_tmp"
      echo "Usage: $0 adblock {status|on|off}"
      return 1
      ;;
  esac

  if ! dnsmasq --test || ! systemctl reload dnsmasq; then
    if (( had_config )); then mv "$config_backup" "$config"; else rm -f "$config"; fi
    if (( had_state )); then mv "$state_backup" "$state"; else rm -f "$state"; fi
    systemctl reload dnsmasq >/dev/null 2>&1 || true
    rm -f "$config_backup" "$state_backup" "$config_tmp" "$state_tmp"
    echo "[ERROR] Ad-block configuration was rejected; previous state restored." >&2
    return 1
  fi

  if ! jq --argjson enabled "$([[ "$choice" == on ]] && printf true || printf false)" \
    '.enabled = $enabled' "$state" >"$state_tmp"; then
    if (( had_config )); then mv "$config_backup" "$config"; else rm -f "$config"; fi
    if (( had_state )); then mv "$state_backup" "$state"; else rm -f "$state"; fi
    systemctl reload dnsmasq >/dev/null 2>&1 || true
    rm -f "$config_backup" "$state_backup" "$config_tmp" "$state_tmp"
    echo "[ERROR] Could not update ad-block state; previous state restored." >&2
    return 1
  fi
  chmod 600 "$state_tmp"
  mv "$state_tmp" "$state"
  rm -f "$config_backup" "$state_backup" "$config_tmp"
  show_adblock
}

restart_all() {
  local failures=0 restarted=0
  echo "Restarting active VPN services can disconnect clients."
  for unit in "${MANAGED_SERVICES[@]}"; do
    if systemctl is-active --quiet "$unit"; then
      if systemctl restart "$unit"; then
        printf 'restarted: %s\n' "$unit"
        ((restarted += 1))
      else
        printf 'failed: %s\n' "$unit" >&2
        ((failures += 1))
      fi
    fi
  done
  (( restarted > 0 )) || echo "No managed services were active."
  (( failures == 0 ))
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    status) show_status; exit 0 ;;
    protocols) show_protocols; exit 0 ;;
    cert) check_cert; exit 0 ;;
    domain) show_domain_guide; exit 0 ;;
    maintenance)
      manage_maintenance_internet "${2:-status}"
      exit $? ;;
    webcheck) check_web_routes; exit $? ;;
    logs) show_recent_logs; exit 0 ;;
    restart) restart_all; exit 0 ;;
    adblock)
      case "${2:-status}" in
        status) show_adblock ;;
        on|off) toggle_adblock "$2" ;;
        *) echo "Usage: $0 {status|protocols|cert|domain|webcheck|logs|restart|adblock {status|on|off}}"; exit 1 ;;
      esac
      exit $? ;;
    *) echo "Usage: $0 {status|protocols|cert|domain|webcheck|logs|restart|adblock {status|on|off}|maintenance {status|internet-on|internet-off}}"; exit 1 ;;
  esac
done

cat <<'MENU'
VPN Management Console
1) Show service status
2) Show protocol summary
3) Check domain certificate handshake
4) Restart all active VPN services
5) Show VPN DNS ad-block status
6) Enable VPN DNS ad blocking
7) Disable VPN DNS ad blocking
8) Check frontend and API routes
9) Show recent service logs
10) Domain and TLS setup guide
11) Maintenance forwarding status
12) Pause WireGuard/OpenVPN internet forwarding
13) Resume WireGuard/OpenVPN internet forwarding
0) Exit
MENU

while true; do
  printf 'Select option: '
  read -r choice || break
  case "$choice" in
    1) show_status ;;
    2) show_protocols ;;
    3) check_cert ;;
    4)
      read -r -p 'Restart active services? VPN clients may disconnect [y/N]: ' confirm
      [[ "$confirm" == [yY] ]] && restart_all || echo "Restart cancelled."
      ;;
    5) show_adblock ;;
    6) toggle_adblock on ;;
    7) toggle_adblock off ;;
    8) check_web_routes ;;
    9) show_recent_logs ;;
    10) show_domain_guide ;;
    11) manage_maintenance_internet status ;;
    12)
      read -r -p 'Pause IPv4 internet forwarding for WireGuard/OpenVPN clients? [y/N]: ' confirm
      [[ "$confirm" == [yY] ]] && manage_maintenance_internet internet-on || echo "Pause cancelled."
      ;;
    13) manage_maintenance_internet internet-off ;;
    0) exit 0 ;;
    *) echo "Invalid option" ;;
  esac
done
