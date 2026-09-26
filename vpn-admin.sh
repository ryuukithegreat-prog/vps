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

toggle_adblock() {
  local choice="${1:-}"
  case "$choice" in
    on)
      printf 'addn-hosts=/var/lib/vpnfront/ads.hosts\n' >/etc/dnsmasq.d/vpnfront-adblock.conf
      dnsmasq --test && systemctl reload dnsmasq
      jq '.enabled = true' /var/lib/vpnfront/adblock.json >/var/lib/vpnfront/adblock.json.tmp && mv /var/lib/vpnfront/adblock.json.tmp /var/lib/vpnfront/adblock.json
      ;;
    off)
      rm -f /etc/dnsmasq.d/vpnfront-adblock.conf
      dnsmasq --test && systemctl reload dnsmasq
      jq '.enabled = false' /var/lib/vpnfront/adblock.json >/var/lib/vpnfront/adblock.json.tmp && mv /var/lib/vpnfront/adblock.json.tmp /var/lib/vpnfront/adblock.json
      ;;
    *) echo "Usage: $0 adblock {status|on|off}"; return 1 ;;
  esac
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
    webcheck) check_web_routes; exit $? ;;
    logs) show_recent_logs; exit 0 ;;
    restart) restart_all; exit 0 ;;
    adblock)
      case "${2:-status}" in
        status) show_adblock ;;
        on|off) toggle_adblock "$2" ;;
        *) echo "Usage: $0 {status|protocols|cert|webcheck|logs|restart|adblock {status|on|off}}"; exit 1 ;;
      esac
      exit $? ;;
    *) echo "Usage: $0 {status|protocols|cert|webcheck|logs|restart|adblock {status|on|off}}"; exit 1 ;;
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
    0) exit 0 ;;
    *) echo "Invalid option" ;;
  esac
done
