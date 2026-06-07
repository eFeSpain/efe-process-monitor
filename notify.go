package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const notifyThrottle = 60 * time.Second

var (
	notifyMu      sync.Mutex
	lastNotify    = map[string]time.Time{}
	notifyDesktop = true // toggled from Settings (persisted as NOTIFY_DESKTOP)
	notifySound   = true // play the toast sound? (persisted as NOTIFY_SOUND)
)

var (
	iconOnce sync.Once
	iconPath string // absolute path to the extracted PNG, used as the toast IconUri
)

// notifyIcon extracts the embedded app icon to disk once and returns its path,
// so Windows toasts can show the real program icon via the AppUserModelID. The
// toast reads an on-disk file (it can't use an embedded resource). Returns ""
// if extraction fails (notifications then just fall back to no custom icon).
func notifyIcon() string {
	iconOnce.Do(func() {
		data, err := staticFS.ReadFile("web/static/icon.png")
		if err != nil {
			return
		}
		p := filepath.Join(appDir, "icon.png")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return
		}
		iconPath = p
	})
	return iconPath
}

// notify shows a best-effort desktop notification, throttled per key.
func notify(title, message, key string) {
	if !notifyDesktop {
		return
	}
	if key == "" {
		key = message
	}
	notifyMu.Lock()
	if time.Since(lastNotify[key]) < notifyThrottle {
		notifyMu.Unlock()
		return
	}
	lastNotify[key] = time.Now()
	notifyMu.Unlock()
	go sendNotification(title, message)
}

func sendNotification(title, message string) {
	if runtime.GOOS == "linux" {
		args := []string{"-u", "critical"}
		if ic := notifyIcon(); ic != "" { // real app icon, same one extracted for Windows toasts
			args = append(args, "-i", ic)
		}
		args = append(args, title, message)
		if command("notify-send", args...).Start() == nil {
			return
		}
		log.Printf("NOTIFY: %s — %s", title, message)
		return
	}
	if runtime.GOOS != "windows" {
		log.Printf("NOTIFY: %s — %s", title, message)
		return
	}
	// Modern Windows toast attributed to our own app name. We register an
	// AppUserModelID in HKCU (no admin) with a DisplayName, then raise the toast
	// with that AppID so it shows "eFe Process Monitor", not "Windows PowerShell".
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	silent := "" // mute the toast's system sound unless sound is enabled
	if !notifySound {
		silent = "$a=$x.CreateElement('audio');$a.SetAttribute('silent','true');" +
			"$x.GetElementsByTagName('toast').Item(0).AppendChild($a)|Out-Null;"
	}
	icon := "" // register the real app icon so the toast shows it (not a generic glyph)
	if p := notifyIcon(); p != "" {
		icon = fmt.Sprintf(
			"New-ItemProperty -Path $p -Name IconUri -Value '%s' -PropertyType String -Force|Out-Null;"+
				"New-ItemProperty -Path $p -Name IconBackgroundColor -Value '#00000000' -PropertyType String -Force|Out-Null;",
			esc(p))
	}
	ps := fmt.Sprintf(
		"$ErrorActionPreference='SilentlyContinue';"+
			"$p='HKCU:\\Software\\Classes\\AppUserModelID\\eFe.ProcessMonitor';"+
			"if(-not(Test-Path $p)){New-Item -Path $p -Force|Out-Null};"+
			"New-ItemProperty -Path $p -Name DisplayName -Value 'eFe Process Monitor' -PropertyType String -Force|Out-Null;"+
			"%s"+
			"[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;"+
			"$x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"+
			"$t=$x.GetElementsByTagName('text');"+
			"$t.Item(0).AppendChild($x.CreateTextNode('%s'))|Out-Null;"+
			"$t.Item(1).AppendChild($x.CreateTextNode('%s'))|Out-Null;"+
			"%s"+
			"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('eFe.ProcessMonitor').Show([Windows.UI.Notifications.ToastNotification]::new($x))",
		icon, esc(title), esc(message), silent)
	if err := command("powershell", "-NoProfile", "-Command", ps).Run(); err != nil {
		log.Printf("notify failed: %v", err)
	}
}
