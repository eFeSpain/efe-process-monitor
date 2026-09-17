//go:build linux

package main

import (
	_ "embed"
	"log"
	"net"
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
	// Each step is logged on failure: "no tray" has three different causes
	// (no bus, the bus refusing this uid, a bus with no tray host) and they
	// call for three different fixes.
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		log.Printf("[tray] sin bus de sesión (%s): %v", os.Getenv("DBUS_SESSION_BUS_ADDRESS"), err)
		return false
	}
	defer conn.Close()
	if err = conn.Auth(nil); err != nil {
		log.Printf("[tray] el bus de sesión rechaza la autenticación de uid=%d: %v", os.Getuid(), err)
		return false
	}
	if err = conn.Hello(); err != nil {
		log.Printf("[tray] Hello en el bus de sesión falló: %v", err)
		return false
	}
	obj := conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	for _, name := range []string{
		"org.kde.StatusNotifierWatcher",
		"org.freedesktop.StatusNotifierWatcher",
	} {
		var hasOwner bool
		err := obj.Call("org.freedesktop.DBus.NameHasOwner", 0, name).Store(&hasOwner)
		if err == nil && hasOwner {
			return true
		}
		if err != nil {
			log.Printf("[tray] NameHasOwner(%s) falló: %v", name, err)
		}
	}
	return false
}

func runApp(ln net.Listener, url string) {
	// Decide the tray before starting the server, so noTrayMode is set before
	// the first HTTP request arrives.
	viaHelper := false
	if os.Geteuid() == 0 {
		// Root cannot join the user's session bus (see desktop_linux.go): the
		// icon is shown by a helper copy running as the logged-in user.
		if s := desktopUser(); s == nil {
			noTrayMode, noTrayRoot = true, true
		} else if spawnTrayHelper(tokenURL(url, localToken), s) {
			viaHelper = true
			log.Printf("[tray] icono mostrado en la sesión de %s (uid=%d)", s.name, s.uid)
		} else {
			noTrayMode = true
		}
	} else if !hasTraySupport() {
		noTrayMode = true
	}

	go func() {
		if err := newServer().Serve(ln); err != nil {
			log.Fatal(err)
		}
	}()

	if viaHelper {
		select {} // the helper relays Quit; the server runs in the goroutine above
	}
	if noTrayMode {
		if noTrayRoot {
			log.Println("[tray] Icono de bandeja no disponible: root sin sesión gráfica de usuario identificable (SUDO_UID / PKEXEC_UID).")
			log.Println("[tray] Lánzalo con sudo desde tu sesión de escritorio.")
		} else {
			log.Println("[tray] Icono de bandeja no disponible: no hay StatusNotifierWatcher en el bus de sesión.")
			log.Println("[tray] Si usas GNOME, instala: AppIndicator and KStatusNotifierItem Support")
		}
		log.Println("[tray] El botón 'Detener servicio' está disponible en el panel web.")
		select {} // block; server runs in the goroutine above
	}

	runTray(func() { openDashboard(url) }, func() {})
}

// runTray shows the icon and blocks. open runs on "Open panel"; quit runs on
// "Quit", right before the process exits.
func runTray(open, quit func()) {
	systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle("eFe Process Monitor")
		systray.SetTooltip("eFe Process Monitor v" + appVersion)

		mOpen := systray.AddMenuItem("Abrir panel / Open", "Abrir el panel en el navegador")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Detener / Quit", "Detener el monitor y salir")

		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					open()
				case <-mQuit.ClickedCh:
					quit()
					systray.Quit()
					os.Exit(0)
				}
			}
		}()
	}, func() {})
}
