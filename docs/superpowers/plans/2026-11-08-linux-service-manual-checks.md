# Linux service — manual checks (root + systemd + a desktop session)

What the hermetic tests cannot prove. Run as the desktop user unless a line says
`sudo`. Watch `/opt/efemon/efemon.log` (`sudo tail -f`) throughout.

Build first: `CGO_ENABLED=0 go build -o /tmp/efemon-test/efemon .` and put a `.env`
next to it (any `REFRESH_SECS=10` line is enough to prove migration).

| # | Step | Expect |
|---|------|--------|
| a | `sudo /tmp/efemon-test/efemon --install-service` | prints "installed and started"; `/opt/efemon/.env` exists and `/tmp/efemon-test/.env` is gone; `systemctl is-active efemon` → `active`; tray icon appears within ~5 s; log: `[service] binario instalado`, `[service] datos movidos`, `[+] Mode systemd service (desktop session: waiting…)`, then `[tray] icono mostrado en la sesión de <you>` |
| b | reboot; before logging in, from a TTY: `systemctl is-active efemon` | `active`; after login the tray icon appears; log shows the attach line after your login time |
| c | log out, log in | log: `[tray] sesión de <you> cerrada; esperando otra` then `[tray] icono mostrado…`; `pgrep -af tray-helper \| wc -l` → 1 |
| d | tray → *Stop until next boot* | `systemctl is-active efemon` → `inactive`; `systemctl is-enabled efemon` → `enabled`; `sudo systemctl start efemon` brings it back, icon returns |
| e | panel → ⚙ Settings → login on, set `LISTEN_ADDR=127.0.0.1:5077` → *Restart now* | log: `restarting via UI…`, unit restarts (`systemctl show -p NRestarts efemon` increments or `journalctl -u efemon` shows a stop/start); page reloads on `:5077` |
| f | `efemon` (no sudo) | browser opens on the gate page with the sentence about the tray icon / `sudo efemon`; then `sudo efemon` → opens the panel |
| g | `sudo systemctl stop efemon`; `sudo /tmp/efemon-test/efemon` (manual, holds the port); `sudo systemctl start efemon` | `journalctl -u efemon -n 5` shows `puerto … ocupado … saliendo con error`; `systemctl is-active` → `activating`/`failed` loop; stop the manual one → within ~12 s the service is `active` |
| h | `sudo efemon --uninstall-service` | prints the keep-data notice; `/etc/systemd/system/efemon.service` gone; `/opt/efemon` still there |
| i | fresh scratch dir with `.env`; `sudo ./efemon` (manual, elevated); ⚙ Settings → *Install as a service* → confirm | message "installed — the service starts in a few seconds…", page reloads against the service; `/opt/efemon/.env` present; `grep Environment /etc/systemd/system/efemon.service` → nothing (line removed on first start); log: `[service] datos movidos desde <scratch dir>` |
| j | ⚙ Settings → *Remove service* (from the service itself) | reply `✓` arrives before the service stops; `systemctl is-active` → `inactive`; unit file gone |

Anything that does not match is a finding: note the step letter and the log lines.
