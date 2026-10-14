#!/usr/bin/env bash
# Integration tests. They MODIFY the system: run only as root inside a disposable
# Debian/Ubuntu container, e.g.
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash tests/integration.sh
set -Eeuo pipefail

cd "$(dirname "$0")/.."
H=./harden.sh
PASS=0

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || fail "run as root inside a throwaway container"
[[ -f /.dockerenv || -n ${CI:-} || -n ${HARDEN_I_AM_IN_A_CONTAINER:-} ]] \
  || fail "refusing to run outside a container (set HARDEN_I_AM_IN_A_CONTAINER=1 to override)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server iproute2 procps sudo >/dev/null
mkdir -p /run/sshd

echo "audit"
set +e; $H audit --no-color >/tmp/audit.txt; rc=$?; set -e
[[ $rc -le 1 ]] || fail "audit exit code $rc"
grep -q "Summary:" /tmp/audit.txt && ok "audit prints a summary"
grep -q "SSH .*Password authentication enabled" /tmp/audit.txt && ok "audit flags password authentication"
$H audit --markdown >/tmp/audit.md || true
grep -q '^| Status | Area | Finding |' /tmp/audit.md && ok "markdown report has a table"

echo "dry-run changes nothing"
before=$(find /etc -type f -newer /etc/hostname 2>/dev/null | sort | md5sum)
$H apply --dry-run --no-color >/tmp/dry.txt 2>&1
after=$(find /etc -type f -newer /etc/hostname 2>/dev/null | sort | md5sum)
[[ $before == "$after" ]] && ok "no files changed by --dry-run"
grep -q "NO account has an SSH key" /tmp/dry.txt && ok "warns when nobody has an SSH key"

echo "lockout protection"
$H apply --yes --no-color --skip firewall --skip fail2ban --skip updates --skip sysctl >/dev/null 2>&1
if grep -q '^PasswordAuthentication' /etc/ssh/sshd_config.d/00-hardening.conf; then
  fail "disabled passwords with no key present"
fi
ok "keeps password login when no key exists"
sshd -t && ok "sshd accepts the generated config"

echo "admin with key"
id ops >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo ops
install -d -m 700 -o ops -g ops /home/ops/.ssh
ssh-keygen -q -t ed25519 -N "" -f /tmp/k <<<y >/dev/null 2>&1
install -m 600 -o ops -g ops /tmp/k.pub /home/ops/.ssh/authorized_keys
$H apply --yes --no-color --skip firewall --skip fail2ban --skip updates --skip sysctl >/dev/null 2>&1
grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config.d/00-hardening.conf && ok "disables passwords once ops has a key"
grep -q '^PermitRootLogin no' /etc/ssh/sshd_config.d/00-hardening.conf && ok "disables root login"
[[ $(sshd -T | awk '$1=="passwordauthentication"{print $2}') == no ]] && ok "effective sshd config: passwords off"
ls /var/backups/linux-hardening-kit/*/etc/ssh/sshd_config.d/00-hardening.conf >/dev/null && ok "previous file backed up"

echo "rollback on invalid sshd config"
echo "BogusDirective yes" >/etc/ssh/sshd_config.d/99-broken.conf
rm -f /etc/ssh/sshd_config.d/00-hardening.conf
set +e; $H apply --yes --no-color --skip firewall --skip fail2ban --skip updates --skip sysctl >/dev/null 2>&1; rc=$?; set -e
rm -f /etc/ssh/sshd_config.d/99-broken.conf
[[ $rc -ne 0 && ! -f /etc/ssh/sshd_config.d/00-hardening.conf ]] && ok "rolls back and exits non-zero"

echo "updates + sysctl"
$H apply --yes --no-color --skip ssh --skip firewall --skip fail2ban >/dev/null 2>&1
grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades && ok "automatic updates enabled"
[[ -f /etc/sysctl.d/60-hardening.conf ]] && ok "sysctl file written"
$H apply --yes --no-color --skip ssh --skip firewall --skip fail2ban >/tmp/second.txt 2>&1
grep -q "unchanged: /etc/sysctl.d/60-hardening.conf" /tmp/second.txt && ok "second run is idempotent"

echo ""
EXPECTED=15
[[ $PASS -eq $EXPECTED ]] || fail "only $PASS of $EXPECTED checks passed"
echo "$PASS checks passed"
