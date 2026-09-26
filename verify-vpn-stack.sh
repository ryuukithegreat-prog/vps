#!/usr/bin/env bash
set -Eeuo pipefail

failures=0

pass() {
  printf '[PASS] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*"
}

fail() {
  printf '[FAIL] %s\n' "$*"
  failures=$((failures + 1))
}

check_command() {
  local command_name="$1"
  if command -v "$command_name" >/dev/null 2>&1; then
    pass "command available: ${command_name}"
  else
    warn "command unavailable: ${command_name} (expected when run outside an installed VPS)"
  fi
}

check_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    pass "file exists: ${path}"
  else
    fail "missing file: ${path}"
  fi
}

check_shell_syntax() {
  local path="$1"
  if bash -n "$path"; then
    pass "$path parses"
  else
    fail "$path has shell syntax errors"
  fi
}

printf 'VPN stack verification\n=======================\n'

for command_name in bash python3 openssl; do
  check_command "$command_name"
done

check_shell_syntax setup-vpn-stack.sh
check_shell_syntax vpn-admin.sh
check_shell_syntax cert-check.sh
if python3 -m py_compile vpn-status.py admin-api.py; then
  pass "VPN Python services compile"
else
  fail "VPN Python services have syntax errors"
fi
if python3 -m unittest discover -s tests -p 'test_*.py'; then
  pass "VPN status parser tests pass"
else
  fail "VPN status parser tests failed"
fi

grep -q 'HTTP/1.1:CHKDARKMASTER' setup-vpn-stack.sh \
  && pass 'HTTP/1.1 CHKDARKMASTER map is present' \
  || fail 'HTTP/1.1 CHKDARKMASTER map is missing'
grep -q 'OnCalendar=\*-\*-\* 00:00:00' setup-vpn-stack.sh \
  && pass 'midnight restart schedule is present' \
  || fail 'midnight restart schedule is missing'
grep -q 'OnUnitActiveSec=30s' setup-vpn-stack.sh \
  && pass 'status refresh schedule is present' \
  || fail 'status refresh schedule is missing'
grep -q 'proxy_pass http://127.0.0.1:8081' setup-vpn-stack.sh \
  && pass 'admin API uses the loopback proxy' \
  || fail 'admin API loopback proxy is missing'
if grep -q 'alias /var/lib/vpnfront/status.json' setup-vpn-stack.sh; then
  fail 'status JSON is publicly exposed through a static alias'
else
  pass 'status JSON is not publicly aliased'
fi
grep -q 'Secure; SameSite=Strict' admin-api.py \
  && pass 'admin session cookies are secure' \
  || fail 'secure admin session cookie settings are missing'
check_file admin-api.py
check_file web-panel/console.js
check_file web-panel/portal.html
check_file web-panel/portal.js
check_file web-panel/portal.css
grep -q 'try_files /portal.html =404' setup-vpn-stack.sh \
  && pass 'domain root serves the client portal' \
  || fail 'client portal root route is missing'
grep -q 'location ^~ /admin/' setup-vpn-stack.sh \
  && pass 'admin console remains under /admin/' \
  || fail 'admin console route is missing'
grep -q '"/api/portal/login"' admin-api.py \
  && pass 'client portal login API is present' \
  || fail 'client portal login API is missing'
grep -q 'vpn-admin-api.service' setup-vpn-stack.sh \
  && pass 'admin API service is installed' \
  || fail 'admin API service install is missing'
grep -q 'name="password"' web-panel/index.html \
  && pass 'panel sign-in form is present' \
  || fail 'panel sign-in form is missing'
grep -q 'DEFAULT_UDPGW_PORT=7300' setup-vpn-stack.sh \
  && pass 'UDPGW port is explicitly named' \
  || fail 'UDPGW port declaration is missing'

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  check_file /etc/nginx/conf.d/vpn_frontend.conf
  check_file /etc/systemd/system/vpnfront-restart.timer
  check_file /etc/systemd/system/vpn-status-refresh.timer
  check_file /etc/systemd/system/vpn-admin-api.service
  check_file /etc/ssh/banner

  if command -v nginx >/dev/null 2>&1; then
    nginx -t >/dev/null 2>&1 && pass 'nginx configuration validates' || fail 'nginx configuration failed validation'
  fi

  if command -v sshd >/dev/null 2>&1; then
    sshd -t && pass 'sshd configuration validates' || fail 'sshd configuration failed validation'
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-enabled vpnfront-restart.timer >/dev/null 2>&1 \
      && pass 'midnight restart timer is enabled' \
      || warn 'midnight restart timer is not enabled on this host'
  fi
else
  warn 'not running as root; skipped live Nginx, SSH, systemd, and filesystem checks'
fi

if (( failures > 0 )); then
  printf '\nVerification completed with %d failure(s).\n' "$failures"
  exit 1
fi

printf '\nVerification completed successfully.\n'
