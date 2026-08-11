//go:build windows

package main

import (
	_ "embed"
	"log"
	"net"
	"os"

	"fyne.io/systray"
)

//go:embed web/static/icon.ico
var trayIcon []byte

// runApp serves HTTP in the background and shows a system-tray icon with a menu.
func runApp(ln net.Listener, url string) {
	go func() {
		if err := newServer().Serve(ln); err != nil {
			log.Fatal(err)
		}
	}()
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
				openDashboard(url)
			case <-mQuit.ClickedCh:
				systray.Quit()
				os.Exit(0)
			}
		}
	}()
}
