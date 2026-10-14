> Real output of `sudo ./harden.sh audit --markdown` on an Ubuntu 24.04 test container before running `apply`. This is the kind of one-page report you can hand to a client.

# Server hardening report: vm

Generated 2026-10-14 18:30 -03 by linux-hardening-kit 0.1.0. Read-only audit, no changes were made.

| Status | Area | Finding |
|---|---|---|
| ✅ OK | OS | Ubuntu 24.04.5 LTS |
| ⚠️ WARN | UPDATES | 55 security update(s) pending (59 total, as of last apt update) |
| ⚠️ WARN | UPDATES | Automatic security updates are not enabled |
| ⚠️ WARN | SSH | Root can log in with a key (PermitRootLogin without-password) |
| ❌ FAIL | SSH | Password authentication enabled: exposed to brute force |
| ⚠️ WARN | SSH | MaxAuthTries is 6 (4 or less recommended) |
| ⚠️ WARN | SSH | X11 forwarding enabled |
| ❌ FAIL | FIREWALL | No active host firewall found (ufw/nftables/iptables) |
| ⚠️ WARN | FAIL2BAN | fail2ban not installed: SSH brute force is not throttled |
| ✅ OK | ACCOUNTS | Only root has UID 0 |
| ✅ OK | ACCOUNTS | No accounts with an empty password |
| ⚠️ WARN | KERNEL | 7 sysctl setting(s) not hardened: net.ipv4.conf.all.accept_redirects=1 net.ipv4.conf.default.accept_redirects=1 net.ipv4.conf.all.send_redirects=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.all.log_martians=0 kernel.kptr_restrict=0 fs.protected_symlinks=0 |
| ℹ️ INFO | NETWORK | Listening on non-loopback addresses: 2024/tcp 2025/tcp |

**Summary:** 3 OK, 1 INFO, 7 WARN, 2 FAIL
