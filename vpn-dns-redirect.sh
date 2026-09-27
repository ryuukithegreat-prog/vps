#!/usr/bin/env bash
set -Eeuo pipefail

action="${1:-}"
interfaces=("wg0:10.42.0.1" "tun0:10.8.0.1")

case "$action" in
  enable)
    for item in "${interfaces[@]}"; do
      interface="${item%%:*}"
      resolver="${item#*:}"
      for protocol in udp tcp; do
        if ! iptables -w -t nat -C PREROUTING -i "$interface" -p "$protocol" --dport 53 -j DNAT --to-destination "$resolver:53" 2>/dev/null; then
          iptables -w -t nat -I PREROUTING 1 -i "$interface" -p "$protocol" --dport 53 -j DNAT --to-destination "$resolver:53"
        fi
      done
    done
    ;;
  disable)
    for item in "${interfaces[@]}"; do
      interface="${item%%:*}"
      resolver="${item#*:}"
      for protocol in udp tcp; do
        while iptables -w -t nat -D PREROUTING -i "$interface" -p "$protocol" --dport 53 -j DNAT --to-destination "$resolver:53" 2>/dev/null; do
          :
        done
      done
    done
    ;;
  *)
    echo "Usage: $0 {enable|disable}" >&2
    exit 2
    ;;
esac