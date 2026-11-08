# Linux service — manual checks (root + systemd + a desktop session)

What the hermetic tests cannot prove. Run as the desktop user unless a line says
`sudo`. Watch `/opt/efemon/efemon.log` (`sudo tail -f`) throughout.

Build first: `CGO_ENABLED=0 go build -o /tmp/efemon-test/efemon .` and put a `.env`
next to it (any `REFRESH_SECS=10` line is enough to prove migration).

| # | Step | Expect |
|---|------|--------|
| a | `sudo /tmp/efemon-test/efemon --install-service` — **the scratch path must contain a space** (e.g. `/tmp/efemon test/`) | prints "installed and started"; `/opt/efemon/.env` exists and `/tmp/efemon-test/.env` is gone; `systemctl is-active efemon` → `active`; tray icon appears within ~5 s; log: `[service] binario instalado`, `[service] datos movidos`, `[+] Mode systemd service (desktop session: waiting…)`, then `[tray] icono mostrado en la sesión de <you>` |
| b | reboot; before logging in, from a TTY: `systemctl is-active efemon` | `active`; after login the tray icon appears — note how long it takes, across 3 reboots (Plasma registers its tray host seconds after the display; the helper is retried after 15 s if it was too early); log shows `[tray] sesión gráfica…` then the attach line |
| c | log out; **before logging in**, from a TTY: `pgrep -af tray-helper` | → nothing (the watcher killed the lingering helper); then log in: log `[tray] sesión de <you> cerrada; esperando otra`, `[tray] sesión gráfica de <you>`, `[tray] icono mostrado…`; `pgrep -af tray-helper \| wc -l` → 1 |
| d | tray → *Stop until next boot* | `systemctl is-active efemon` → `inactive`; `systemctl is-enabled efemon` → `enabled`; `sudo systemctl start efemon` brings it back, icon returns |
| e | panel → ⚙ Settings → login on, set `LISTEN_ADDR=127.0.0.1:5077` → *Restart now* | log: `restarting via UI…`, unit restarts (`systemctl show -p NRestarts efemon` increments or `journalctl -u efemon` shows a stop/start); page reloads on `:5077` |
| f | `efemon` (no sudo; `/usr/local/bin/efemon` is the install's link) | browser opens on the gate page with the sentence about the tray icon / `sudo efemon`; then `sudo efemon` → opens the panel |
| g | `sudo systemctl stop efemon`; `sudo /tmp/efemon-test/efemon` (manual, holds the port); `sudo systemctl start efemon` | `journalctl -u efemon -n 5` shows `puerto … ocupado … saliendo con error`; `systemctl is-active` → `activating`/`failed` loop; stop the manual one → within ~12 s the service is `active` |
| h | `sudo efemon --uninstall-service` | prints the keep-data notice; `/etc/systemd/system/efemon.service` and `/usr/local/bin/efemon` gone; `/opt/efemon` still there |
| h2 | reinstall over a running service: `sudo efemon --install-service` twice, the second with a rebuilt binary | log `[service] servicio reiniciado con el binario nuevo`; `systemctl show -p NRestarts efemon` incremented |
| i | fresh scratch dir **with a space in its path** and a `.env`; `sudo ./efemon` (manual, elevated); ⚙ Settings → *Install as a service* → confirm | message "installed — the service starts in a few seconds…", page reloads against the service; `/opt/efemon/.env` present; `grep Environment /etc/systemd/system/efemon.service` → nothing (line removed on first start); log: `[service] datos movidos desde <scratch dir>` |
| j | ⚙ Settings → *Remove service* (from the service itself) | reply `✓` arrives before the service stops; `systemctl is-active` → `inactive`; unit file **and** `/usr/local/bin/efemon` gone; `sudo efemon --service-status` → `installed=false` |
| k | with the service active and the desktop logged in: `notify-send` path — trigger any alert (e.g. kill a process from the panel) | desktop notification appears; log has no `NOTIFY:` fallback lines (notifications reach the session even when the tray host is late) |

Anything that does not match is a finding: note the step letter and the log lines.
