# linux-hardening-kit

[![tests](https://github.com/francisco-vilaca/linux-hardening-kit/actions/workflows/tests.yml/badge.svg)](https://github.com/francisco-vilaca/linux-hardening-kit/actions/workflows/tests.yml) ![license](https://img.shields.io/badge/license-MIT-blue)

Audit and harden Debian/Ubuntu servers **without locking yourself out**.

A single Bash script with two modes:

- **`audit`**: read-only checks with a clear OK / WARN / FAIL report, as plain text or as a Markdown report you can hand to a client.
- **`apply`**: applies a sensible baseline (SSH, firewall, fail2ban, automatic security updates, kernel/network sysctl), with `--dry-run` to preview every change, backups of every file it touches, and safety checks so you don't lose access.

```
$ sudo ./harden.sh audit

linux-hardening-kit 0.1.0: audit of web01

  OS         OK    Ubuntu 24.04.1 LTS
  UPDATES    WARN  12 security update(s) pending (31 total, as of last apt update)
  UPDATES    WARN  Automatic security updates are not enabled
  SSH        WARN  Root can log in with a key (PermitRootLogin prohibit-password)
  SSH        FAIL  Password authentication enabled: exposed to brute force
  SSH        WARN  MaxAuthTries is 6 (4 or less recommended)
  FIREWALL   FAIL  No active host firewall found (ufw/nftables/iptables)
  FAIL2BAN   WARN  fail2ban not installed: SSH brute force is not throttled
  ACCOUNTS   OK    Only root has UID 0
  ACCOUNTS   OK    No accounts with an empty password
  KERNEL     WARN  5 sysctl setting(s) not hardened: ...
  TIME       OK    Clock synchronized (NTP)
  NETWORK    INFO  Listening on non-loopback addresses: 22/tcp 80/tcp 443/tcp

  Summary: 4 OK, 1 INFO, 6 WARN, 2 FAIL
```

## Safety first

Hardening scripts are dangerous when they assume things. This one checks before it acts:

- **No SSH lockout.** Password login is only disabled if a non-root user that can `sudo` already has a valid key in `~/.ssh/authorized_keys`. If only root has a key, root keeps key-only access. If **nobody** has a key, root and password settings are left untouched and you get a loud warning.
- **Config is validated before reload.** The SSH settings go into `/etc/ssh/sshd_config.d/00-hardening.conf`, then `sshd -t` checks them. If sshd rejects the config, the change is rolled back and sshd is never reloaded.
- **Cloud images handled.** The file is named `00-` on purpose: sshd uses the *first* value it reads, so it wins over cloud-init's `50-cloud-init.conf`, which often re-enables passwords.
- **Your current SSH port stays open.** The firewall step reads the port from the effective sshd config and from your current session (`$SSH_CONNECTION`) and allows both before enabling ufw.
- **Backups.** Every file is copied to `/var/backups/linux-hardening-kit/<timestamp>/` before it changes.
- **Dry run.** `apply --dry-run` prints every command and every file it would write, and changes nothing.
- **Idempotent.** Running it twice leaves files untouched the second time.

## Usage

```bash
git clone https://github.com/francisco-vilaca/linux-hardening-kit.git
cd linux-hardening-kit

sudo ./harden.sh audit                         # read-only report
sudo ./harden.sh audit --markdown > report.md  # client-ready report

sudo ./harden.sh apply --dry-run               # preview
sudo ./harden.sh apply --allow 80/tcp --allow 443/tcp
sudo ./harden.sh apply --skip firewall         # skip any step: ssh, firewall, fail2ban, updates, sysctl
```

After `apply`, **keep your current session open and test a new SSH login** before you disconnect.

### What `apply` changes

| Step | Change |
|---|---|
| `ssh` | `PermitRootLogin no`, `PasswordAuthentication no` and `KbdInteractiveAuthentication no` (only when safe, see above), `PermitEmptyPasswords no`, `MaxAuthTries 4`, `LoginGraceTime 30`, `X11Forwarding no`, idle session timeout |
| `firewall` | ufw: deny incoming, allow outgoing, rate-limited SSH, plus any `--allow` ports |
| `fail2ban` | `sshd` jail on the real SSH port: 5 failures in 10 min, 1 hour ban |
| `updates` | `unattended-upgrades` with daily security updates |
| `sysctl` | SYN cookies, no ICMP redirects or source routing, reverse-path filtering, martian logging, ASLR, `kptr_restrict`, protected hard/symlinks |

To revert a step, delete the file it wrote (each one starts with `Managed by linux-hardening-kit`) or restore it from the backup folder.

### Exit codes

`audit` exits `1` when any check FAILs and `0` otherwise, so it can run from cron or CI and alert on regressions. `apply` exits non-zero if a step fails (for example, when sshd rejects the config and the change is rolled back).

## Tests

- `shellcheck` runs on every push.
- `tests/integration.sh` runs the real thing inside throwaway **Ubuntu 22.04, Ubuntu 24.04 and Debian 12** containers: audit output, dry-run changing nothing, lockout protection with and without keys, effective sshd config, rollback on an invalid sshd config, backups and idempotency.

```bash
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash tests/integration.sh
```

## Scope

This is a solid baseline for internet-facing Debian/Ubuntu servers, not a full CIS benchmark. It doesn't touch application configs, users or packages beyond `ufw`, `fail2ban` and `unattended-upgrades`.

## License

MIT, see [LICENSE](LICENSE).
