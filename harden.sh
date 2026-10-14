#!/usr/bin/env bash
# linux-hardening-kit: audit and harden Debian/Ubuntu servers without locking yourself out.
#
#   ./harden.sh audit                 read-only report (default)
#   ./harden.sh audit --markdown      same report as Markdown, ready to hand to a client
#   ./harden.sh apply --dry-run       show exactly what would change
#   ./harden.sh apply --yes           apply the changes
#
# https://github.com/francisco-vilaca/linux-hardening-kit  (MIT)

set -Eeuo pipefail

VERSION="0.1.0"

# Paths can be overridden for testing.
ETC="${HARDEN_ETC:-/etc}"
BACKUP_ROOT="${HARDEN_BACKUP_DIR:-/var/backups/linux-hardening-kit}"
# 00- so it is read before cloud-init's 50-cloud-init.conf: in sshd the FIRST value wins.
SSHD_DROPIN="$ETC/ssh/sshd_config.d/00-hardening.conf"
SYSCTL_FILE="$ETC/sysctl.d/60-hardening.conf"
F2B_JAIL="$ETC/fail2ban/jail.d/sshd-hardening.local"
AUTO_UPGRADES="$ETC/apt/apt.conf.d/20auto-upgrades"

MODE="audit"
FORMAT="text"
DRY_RUN=0
ASSUME_YES=0
ADMIN_USER=""
ALLOW_PORTS=()
SKIP=()
NO_COLOR=0

N_OK=0 N_INFO=0 N_WARN=0 N_FAIL=0
BACKUP_DIR=""

SYSCTL_SETTINGS=(
  "net.ipv4.tcp_syncookies=1"
  "net.ipv4.conf.all.accept_redirects=0"
  "net.ipv4.conf.default.accept_redirects=0"
  "net.ipv6.conf.all.accept_redirects=0"
  "net.ipv4.conf.all.send_redirects=0"
  "net.ipv4.conf.all.accept_source_route=0"
  "net.ipv4.conf.all.rp_filter=1"
  "net.ipv4.conf.all.log_martians=1"
  "kernel.randomize_va_space=2"
  "kernel.kptr_restrict=2"
  "fs.protected_hardlinks=1"
  "fs.protected_symlinks=1"
)

usage() {
  cat <<'EOF'
Usage: harden.sh [audit|apply] [options]

Modes:
  audit                Read-only checks (default). Exit code 1 if anything FAILs.
  apply                Harden the server. Combine with --dry-run first.

Options:
  --markdown           Audit output as a Markdown report
  --dry-run            (apply) print every change without making it
  --yes                (apply) do not ask for confirmation
  --admin-user USER    (apply) user whose SSH key must work before password login is disabled
  --allow PORT[/PROTO] (apply) extra port to open in ufw, repeatable (e.g. --allow 443/tcp)
  --skip STEP          (apply) skip a step: ssh, firewall, fail2ban, updates, sysctl (repeatable)
  --no-color           plain output
  -h, --help           this help
  --version            print version
EOF
}

# ------------------------------------------------------------------ output

color() {
  if [[ $NO_COLOR -eq 1 || ! -t 1 || $FORMAT != text ]]; then printf '%s' "$2"; return; fi
  case $1 in
    OK) printf '\033[32m%s\033[0m' "$2" ;;
    INFO) printf '\033[36m%s\033[0m' "$2" ;;
    WARN) printf '\033[33m%s\033[0m' "$2" ;;
    FAIL) printf '\033[31m%s\033[0m' "$2" ;;
    *) printf '%s' "$2" ;;
  esac
}

result() { # result AREA STATUS MESSAGE
  local area=$1 status=$2 msg=$3
  case $status in
    OK) N_OK=$((N_OK + 1)) ;; INFO) N_INFO=$((N_INFO + 1)) ;;
    WARN) N_WARN=$((N_WARN + 1)) ;; FAIL) N_FAIL=$((N_FAIL + 1)) ;;
  esac
  if [[ $FORMAT == markdown ]]; then
    local icon
    case $status in OK) icon="✅" ;; INFO) icon="ℹ️" ;; WARN) icon="⚠️" ;; FAIL) icon="❌" ;; esac
    printf '| %s %s | %s | %s |\n' "$icon" "$status" "$area" "${msg//|/\\|}"
  else
    printf '  %-10s %s  %s\n' "$area" "$(color "$status" "$(printf '%-4s' "$status")")" "$msg"
  fi
}

log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$(color WARN "warning:") $*" >&2; }
die() { printf '%s\n' "$(color FAIL "error:") $*" >&2; exit 2; }

is_root() { [[ $(id -u) -eq 0 ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
systemd_running() { [[ -d /run/systemd/system ]]; }
skipped() { local s; for s in "${SKIP[@]+"${SKIP[@]}"}"; do [[ $s == "$1" ]] && return 0; done; return 1; }

# ------------------------------------------------------------------ sshd helpers

# Effective sshd value. Uses `sshd -T` when possible, otherwise reads the config
# files in the order sshd does (drop-ins first, first value wins).
sshd_value() {
  local key=${1,,} value=""
  if is_root && have sshd && [[ $ETC == /etc ]]; then
    mkdir -p /run/sshd 2>/dev/null || true
    value=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }') || true
  fi
  if [[ -z $value ]]; then
    local files=()
    [[ -d $ETC/ssh/sshd_config.d ]] && while IFS= read -r f; do files+=("$f"); done \
      < <(find "$ETC/ssh/sshd_config.d" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | LC_ALL=C sort)
    [[ -f $ETC/ssh/sshd_config ]] && files+=("$ETC/ssh/sshd_config")
    if ((${#files[@]})); then
      value=$(awk -v k="$key" '
        /^[[:space:]]*#/ { next }
        tolower($1) == "match" { exit }
        tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }' "${files[@]}" 2>/dev/null) || true
    fi
  fi
  if [[ -z $value ]]; then # OpenSSH defaults
    case $key in
      permitrootlogin) value="prohibit-password" ;;
      passwordauthentication | kbdinteractiveauthentication) value="yes" ;;
      x11forwarding) value="no" ;;
      maxauthtries) value="6" ;;
      permitemptypasswords) value="no" ;;
      port) value="22" ;;
    esac
  fi
  printf '%s' "${value,,}"
}

has_valid_key() { # has_valid_key HOME
  local f=$1/.ssh/authorized_keys
  [[ -s $f ]] && grep -Eq '^[^#]*(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-(ssh|ecdsa))' "$f" 2>/dev/null
}

# Prints the first non-root user that can sudo AND has an SSH key, if any.
key_admin() {
  local candidates=() u home
  [[ -n $ADMIN_USER ]] && candidates+=("$ADMIN_USER")
  for g in sudo admin wheel; do
    local members
    members=$(getent group "$g" 2>/dev/null | cut -d: -f4) || true
    IFS=',' read -r -a list <<<"$members"
    candidates+=("${list[@]+"${list[@]}"}")
  done
  for u in "${candidates[@]+"${candidates[@]}"}"; do
    [[ -z $u || $u == root ]] && continue
    home=$(getent passwd "$u" | cut -d: -f6) || continue
    [[ -n $home ]] && has_valid_key "$home" && { printf '%s' "$u"; return 0; }
  done
  return 1
}

# ------------------------------------------------------------------ audit

audit_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ ${ID:-} =~ ^(debian|ubuntu)$ || ${ID_LIKE:-} == *debian* ]]; then
      result OS OK "${PRETTY_NAME:-$ID}"
    else
      result OS WARN "${PRETTY_NAME:-unknown}: only Debian/Ubuntu are tested"
    fi
  fi
  if [[ -f /var/run/reboot-required ]]; then
    result OS WARN "Reboot required to finish installing updates"
  fi
  is_root || result OS INFO "Not running as root: some checks are limited"
}

audit_updates() {
  have apt-get || return 0
  local upgradable security
  upgradable=$(apt list --upgradable 2>/dev/null | grep -vc '^Listing' || true)
  security=$(apt list --upgradable 2>/dev/null | grep -c -- '-security' || true)
  if ((security > 0)); then
    result UPDATES WARN "$security security update(s) pending ($upgradable total, as of last apt update)"
  elif ((upgradable > 0)); then
    result UPDATES INFO "$upgradable non-security update(s) pending"
  else
    result UPDATES OK "No pending updates (as of last apt update)"
  fi
  if pkg_installed unattended-upgrades && grep -qs 'Unattended-Upgrade "1"' "$AUTO_UPGRADES"; then
    result UPDATES OK "Automatic security updates enabled"
  else
    result UPDATES WARN "Automatic security updates are not enabled"
  fi
}

audit_ssh() {
  if ! have sshd && [[ ! -f $ETC/ssh/sshd_config ]]; then
    result SSH INFO "OpenSSH server not installed"
    return
  fi
  local v
  v=$(sshd_value PermitRootLogin)
  case $v in
    no) result SSH OK "Root login disabled" ;;
    prohibit-password | without-password) result SSH WARN "Root can log in with a key (PermitRootLogin $v)" ;;
    *) result SSH FAIL "Root can log in with a password (PermitRootLogin $v)" ;;
  esac
  v=$(sshd_value PasswordAuthentication)
  if [[ $v == no ]]; then result SSH OK "Password authentication disabled"
  else result SSH FAIL "Password authentication enabled: exposed to brute force"; fi
  v=$(sshd_value KbdInteractiveAuthentication)
  [[ $v == no ]] || result SSH WARN "Keyboard-interactive authentication enabled"
  v=$(sshd_value PermitEmptyPasswords)
  [[ $v == no ]] || result SSH FAIL "Empty passwords are allowed"
  v=$(sshd_value MaxAuthTries)
  if [[ $v =~ ^[0-9]+$ ]] && ((v > 4)); then result SSH WARN "MaxAuthTries is $v (4 or less recommended)"; fi
  v=$(sshd_value X11Forwarding)
  [[ $v == no ]] || result SSH WARN "X11 forwarding enabled"
}

audit_firewall() {
  if have ufw && is_root && ufw status 2>/dev/null | grep -q '^Status: active'; then
    result FIREWALL OK "ufw is active"
  elif have nft && is_root && nft list ruleset 2>/dev/null | grep -Eq 'hook input .*policy drop'; then
    result FIREWALL OK "nftables input policy is drop"
  elif have iptables && is_root && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; then
    result FIREWALL OK "iptables INPUT policy is DROP"
  elif ! is_root; then
    result FIREWALL INFO "Run as root to check the firewall"
  else
    result FIREWALL FAIL "No active host firewall found (ufw/nftables/iptables)"
  fi
}

audit_fail2ban() {
  if ! pkg_installed fail2ban; then
    result FAIL2BAN WARN "fail2ban not installed: SSH brute force is not throttled"
  elif pgrep -x fail2ban-server >/dev/null 2>&1; then
    result FAIL2BAN OK "fail2ban is running"
  else
    result FAIL2BAN WARN "fail2ban installed but not running"
  fi
}

audit_accounts() {
  local extra_root empty
  extra_root=$(awk -F: '$3 == 0 && $1 != "root" { printf "%s ", $1 }' /etc/passwd)
  if [[ -n $extra_root ]]; then result ACCOUNTS FAIL "Non-root accounts with UID 0: $extra_root"
  else result ACCOUNTS OK "Only root has UID 0"; fi
  if [[ -r /etc/shadow ]]; then
    empty=$(awk -F: '$2 == "" { printf "%s ", $1 }' /etc/shadow)
    if [[ -n $empty ]]; then result ACCOUNTS FAIL "Accounts with an empty password: $empty"
    else result ACCOUNTS OK "No accounts with an empty password"; fi
  fi
}

audit_sysctl() {
  have sysctl || return 0
  local item key want got bad=()
  for item in "${SYSCTL_SETTINGS[@]}"; do
    key=${item%%=*} want=${item#*=}
    got=$(sysctl -n "$key" 2>/dev/null) || continue
    [[ $got == "$want" ]] || bad+=("$key=$got")
  done
  if ((${#bad[@]})); then result KERNEL WARN "${#bad[@]} sysctl setting(s) not hardened: ${bad[*]}"
  else result KERNEL OK "Network and kernel sysctl settings hardened"; fi
}

audit_time() {
  if have timedatectl && systemd_running; then
    if [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]]; then
      result TIME OK "Clock synchronized (NTP)"
    else
      result TIME WARN "Clock not synchronized: logs and TLS may misbehave"
    fi
  fi
}

audit_listening() {
  have ss || return 0
  local ports
  ports=$(ss -H -tuln 2>/dev/null | awk '{print $1"/"$5}' \
    | grep -Ev '/(127\.[0-9.]+|\[::1\]|::1):' | sed -E 's#^(tcp|udp)/.*:([0-9]+)$#\2/\1#' | sort -un | tr '\n' ' ') || true
  if [[ -n $ports ]]; then result NETWORK INFO "Listening on non-loopback addresses: $ports"
  else result NETWORK OK "No services listening on non-loopback addresses"; fi
}

run_audit() {
  if [[ $FORMAT == markdown ]]; then
    printf '# Server hardening report: %s\n\n' "$(uname -n)"
    printf 'Generated %s by linux-hardening-kit %s. Read-only audit, no changes were made.\n\n' "$(date '+%Y-%m-%d %H:%M %Z')" "$VERSION"
    printf '| Status | Area | Finding |\n|---|---|---|\n'
  else
    log "linux-hardening-kit $VERSION: audit of $(uname -n)"
    log ""
  fi
  audit_os
  audit_updates
  audit_ssh
  audit_firewall
  audit_fail2ban
  audit_accounts
  audit_sysctl
  audit_time
  audit_listening
  local summary="$N_OK OK, $N_INFO INFO, $N_WARN WARN, $N_FAIL FAIL"
  if [[ $FORMAT == markdown ]]; then printf '\n**Summary:** %s\n' "$summary"
  else log ""; log "  Summary: $summary"; fi
  ((N_FAIL == 0))
}

# ------------------------------------------------------------------ apply helpers

step() { log ""; log "$(color INFO "==>") $*"; }

run() {
  if ((DRY_RUN)); then log "    [dry-run] $*"; else "$@"; fi
}

backup() {
  local f=$1
  [[ -e $f ]] || return 0
  if [[ -z $BACKUP_DIR ]]; then BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"; fi
  if ((DRY_RUN)); then log "    [dry-run] back up $f to $BACKUP_DIR"; return; fi
  mkdir -p "$BACKUP_DIR$(dirname "$f")"
  cp -a "$f" "$BACKUP_DIR$f"
}

write_file() { # write_file PATH CONTENT
  local path=$1 content=$2
  if [[ -f $path ]] && [[ $(cat "$path") == "$content" ]]; then
    log "    unchanged: $path"
    return
  fi
  backup "$path"
  if ((DRY_RUN)); then
    log "    [dry-run] write $path:"
    printf '%s\n' "$content" | sed 's/^/      | /'
    return
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" >"$path"
  log "    wrote $path"
}

apt_install() {
  local missing=() p
  for p in "$@"; do pkg_installed "$p" || missing+=("$p"); done
  ((${#missing[@]})) || return 0
  log "    installing: ${missing[*]}"
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o Dpkg::Use-Pty=0 "${missing[@]}" >/dev/null
}

service_reload() { # service_reload NAME [restart]
  if ((DRY_RUN == 0)) && ! systemd_running; then
    warn "systemd is not running; restart $1 manually"
    return
  fi
  run systemctl enable --now "$1" >/dev/null 2>&1 || true
  run systemctl "${2:-reload-or-restart}" "$1"
}

# ------------------------------------------------------------------ apply steps

apply_ssh() {
  step "SSH"
  if ! have sshd; then log "    OpenSSH server not installed, skipping"; return; fi
  if ! grep -Eqs '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$ETC/ssh/sshd_config"; then
    warn "$ETC/ssh/sshd_config does not include sshd_config.d/*.conf; skipping SSH (add the Include line first)"
    return
  fi
  local admin="" root_rule="" auth_rules=""
  if admin=$(key_admin); then
    log "    $admin can sudo and has an SSH key: safe to disable root and password login"
    root_rule="PermitRootLogin no"
    auth_rules=$'PasswordAuthentication no\nKbdInteractiveAuthentication no'
  elif has_valid_key "$(getent passwd root | cut -d: -f6)"; then
    warn "no sudo user with an SSH key; only root has one. Root keeps key login, passwords are disabled."
    root_rule="PermitRootLogin prohibit-password"
    auth_rules=$'PasswordAuthentication no\nKbdInteractiveAuthentication no'
  else
    warn "NO account has an SSH key. Leaving root/password login unchanged to avoid locking you out."
    warn "Add a key with ssh-copy-id, then run apply again (or use --admin-user)."
  fi

  local content="# Managed by linux-hardening-kit $VERSION. Remove this file to revert.
${root_rule:+$root_rule
}${auth_rules:+$auth_rules
}PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2"
  local previous=""
  [[ -f $SSHD_DROPIN ]] && previous=$(cat "$SSHD_DROPIN")
  write_file "$SSHD_DROPIN" "$content"
  ((DRY_RUN)) && return
  mkdir -p /run/sshd 2>/dev/null || true
  if ! sshd -t 2>/tmp/harden-sshd.err; then
    warn "sshd rejected the new config, rolling back: $(cat /tmp/harden-sshd.err)"
    if [[ -n $previous ]]; then printf '%s\n' "$previous" >"$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
    return 1
  fi
  service_reload ssh
  log "    Keep this session open and test a NEW ssh login before closing it."
}

apply_firewall() {
  step "Firewall (ufw)"
  apt_install ufw
  local ssh_port session_port p
  ssh_port=$(sshd_value Port); ssh_port=${ssh_port%% *}
  session_port=$(awk '{print $4}' <<<"${SSH_CONNECTION:-}")
  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw limit "${ssh_port:-22}/tcp" comment "ssh (rate limited)"
  if [[ -n $session_port && $session_port != "$ssh_port" ]]; then
    log "    current session uses port $session_port, allowing it too"
    run ufw allow "$session_port/tcp" comment "current ssh session"
  fi
  for p in "${ALLOW_PORTS[@]+"${ALLOW_PORTS[@]}"}"; do run ufw allow "$p"; done
  run ufw --force enable
}

apply_fail2ban() {
  step "fail2ban"
  apt_install fail2ban
  local ssh_port
  ssh_port=$(sshd_value Port); ssh_port=${ssh_port%% *}
  write_file "$F2B_JAIL" "# Managed by linux-hardening-kit $VERSION
[sshd]
enabled  = true
port     = ${ssh_port:-22}
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h"
  service_reload fail2ban restart
}

apply_updates() {
  step "Automatic security updates"
  apt_install unattended-upgrades
  write_file "$AUTO_UPGRADES" '// Managed by linux-hardening-kit
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";'
}

apply_sysctl() {
  step "Kernel / network sysctl"
  local content="# Managed by linux-hardening-kit $VERSION" item
  for item in "${SYSCTL_SETTINGS[@]}"; do content+=$'\n'"${item%%=*} = ${item#*=}"; done
  write_file "$SYSCTL_FILE" "$content"
  run sysctl -q -p "$SYSCTL_FILE" || warn "some sysctl keys could not be applied (normal in containers)"
}

run_apply() {
  if ! grep -Eqs '^(ID|ID_LIKE)=.*(debian|ubuntu)' /etc/os-release; then
    die "apply supports Debian/Ubuntu only"
  fi
  if ! is_root && ((DRY_RUN == 0)); then die "apply must run as root (use sudo), or add --dry-run"; fi

  log "linux-hardening-kit $VERSION: apply on $(uname -n)$( ((DRY_RUN)) && printf ' (DRY RUN: nothing will change)')"
  local steps=() s
  for s in ssh firewall fail2ban updates sysctl; do skipped "$s" || steps+=("$s"); done
  log "Steps: ${steps[*]:-none}"
  if ((DRY_RUN == 0 && ASSUME_YES == 0)); then
    [[ -t 0 ]] || die "not a terminal: re-run with --yes to confirm, or --dry-run to preview"
    read -r -p "Apply these changes? Run with --dry-run first if unsure. [y/N] " answer
    [[ $answer =~ ^[Yy]$ ]] || die "aborted"
  fi
  ((DRY_RUN)) || apt_install_update_once
  for s in "${steps[@]+"${steps[@]}"}"; do "apply_$s"; done
  log ""
  [[ -n $BACKUP_DIR ]] && log "Backups of changed files: $BACKUP_DIR"
  log "Done. Run './harden.sh audit' to see the result."
}

apt_install_update_once() { run env DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null; }

# ------------------------------------------------------------------ main

main() {
  if [[ $# -gt 0 && $1 =~ ^(audit|apply)$ ]]; then MODE=$1; shift; fi
  while [[ $# -gt 0 ]]; do
    case $1 in
      --markdown) FORMAT=markdown ;;
      --dry-run) DRY_RUN=1 ;;
      --yes | -y) ASSUME_YES=1 ;;
      --admin-user) ADMIN_USER=${2:?--admin-user needs a value}; shift ;;
      --allow) ALLOW_PORTS+=("${2:?--allow needs a port}"); shift ;;
      --skip)
        [[ ${2:-} =~ ^(ssh|firewall|fail2ban|updates|sysctl)$ ]] || die "--skip expects ssh, firewall, fail2ban, updates or sysctl"
        SKIP+=("$2"); shift ;;
      --no-color) NO_COLOR=1 ;;
      -h | --help) usage; exit 0 ;;
      --version) echo "linux-hardening-kit $VERSION"; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
  done
  if [[ $MODE == audit ]]; then run_audit; else run_apply; fi
}

main "$@"
