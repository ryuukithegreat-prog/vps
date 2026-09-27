#!/usr/bin/env bash
set -Eeuo pipefail

chain=VPNFRONT_MAINT
interfaces=(wg0 tun0)
outbound_interface="$(ip -4 route show default | awk 'NR == 1 {print $5}')"
if [[ ! "$outbound_interface" =~ ^[[:alnum:]_.:-]+$ ]]; then
  echo "Could not determine the VPS outbound interface." >&2
  exit 1
fi

remove_rules() {
  for interface in "${interfaces[@]}"; do
    while iptables -w -D FORWARD -i "$interface" -o "$outbound_interface" -j "$chain" 2>/dev/null; do
      :
    done
  done
  iptables -w -F "$chain" 2>/dev/null || true
}

case "${1:-}" in
  enable)
    if ! iptables -w -nL "$chain" >/dev/null 2>&1; then
      iptables -w -N "$chain"
    fi
    iptables -w -F "$chain"
    iptables -w -A "$chain" -j REJECT
    for interface in "${interfaces[@]}"; do
      if ! iptables -w -C FORWARD -i "$interface" -o "$outbound_interface" -j "$chain" 2>/dev/null; then
        iptables -w -I FORWARD 1 -i "$interface" -o "$outbound_interface" -j "$chain"
      fi
    done
    ;;
  disable)
    if iptables -w -nL "$chain" >/dev/null 2>&1; then
      remove_rules
    fi
    ;;
  status)
    active=0
    for interface in "${interfaces[@]}"; do
      if iptables -w -C FORWARD -i "$interface" -o "$outbound_interface" -j "$chain" 2>/dev/null; then
        active=1
      fi
    done
    if (( active )); then
      printf 'enabled\n'
    else
      printf 'disabled\n'
    fi
    ;;
  *)
    echo "Usage: $0 {enable|disable|status}" >&2
    exit 2
    ;;
esac