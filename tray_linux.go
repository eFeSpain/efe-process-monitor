//go:build linux

package main

import (
	_ "embed"
	"log"
	"net"
	"net/http"
	"os"

	"fyne.io/systray"
	"github.com/godbus/dbus/v5"
)

//go:embed web/static/icon.png
var trayIcon []byte

// hasTraySupport checks if a StatusNotifierWatcher is present on the session
// D-Bus, which is required for tray icons to work (KDE native; GNOME needs the
// AppIndicator extension; XFCE/MATE/Cinnamon have it built in).
func hasTraySupport() bool {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return false
	}
	defer conn.Close()
	if err = conn.Auth(nil); err != nil {
		return false
	}
	if err = conn.Hello(); err != nil {
		return false
	}
	obj := conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	for _, name := range []string{
		"org.kde.StatusNotifierWatcher",
		"org.freedesktop.StatusNotifierWatcher",
	} {
		var hasOwner bool
		if err := obj.Call("org.freedesktop.DBus.NameHasOwner", 0, name).Store(&hasOwner); err == nil && hasOwner {
			return true
		}
	}
	return false
}

func runApp(ln net.Listener, url string) {
	// Detect tray support before starting the server so noTrayMode is set
	// before the first HTTP request arrives.
	if !hasTraySupport() {
		noTrayMode = true
	}

	go func() {
		if err := http.Serve(ln, rootHandler()); err != nil {
			log.Fatal(err)
		}
	}()

	if noTrayMode {
		log.Println("[tray] Icono de bandeja no disponible en este entorno.")
		log.Println("[tray] En GNOME instala: AppIndicator and KStatusNotifierItem Support")
		log.Println("[tray] El botón 'Detener servicio' está disponible en el panel web.")
		select {} // block; server runs in the goroutine above
	}

	systray.Run(func() { trayReady(url) }, func() {})
}

func trayReady(url string) {
	systray.SetIcon(trayIcon)
	systray.SetTitle("eFe Process Monitor")
	systray.SetTooltip("eFe Process Monitor — " + url)

	mOpen := systray.AddMenuItem("Abrir panel / Open", "Abrir el panel en el navegador")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Detener / Quit", "Detener el monitor y salir")

	go func() {
		for {
			select {
			case <-mOpen.ClickedCh:
				openBrowser(url)
			case <-mQuit.ClickedCh:
				systray.Quit()
				os.Exit(0)
			}
		}
	}()
}
