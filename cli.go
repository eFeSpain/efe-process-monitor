package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Command-line options. Until 0.4.x the only argument was the internal
// --tray-helper; running as a service needs a few more, and a service manager
// or a script has no other interface to the binary than these.

type options struct {
	Version   bool // print the version and exit
	NoBrowser bool // start without opening the browser
	Service   bool // service mode: no browser, session watcher, systemctl for quit/restart
	Install   bool // install as a systemd service and exit
	Uninstall bool // remove the systemd service and exit
	Status    bool // print the service status and exit
}

// serviceMode is set by main through inferServiceMode; noBrowser is
// --no-browser or service mode.
var serviceMode, noBrowser bool

// inferServiceMode decides whether this process is the systemd service: the
// --service flag, or started by systemd itself (INVOCATION_ID set) *as a
// direct child of PID 1*. The variable alone is not enough: systemd also
// starts the user's graphical session, so every terminal and editor under it
// inherits INVOCATION_ID — and a user program must not go quiet (no browser,
// Quit → systemctl stop) because of where it was launched from.
func inferServiceMode(flag bool, invocationID string, ppid int) bool {
	return flag || (invocationID != "" && ppid == 1)
}

// ServiceStatus is what /api/service and --service-status report. Declared here,
// not in the platform files, so both of them fill the same shape.
type ServiceStatus struct {
	Supported bool   `json:"supported"`
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	Mode      string `json:"mode"` // "service" or "manual"
	Path      string `json:"path"`
	Elevated  bool   `json:"elevated"`
}

// parseArgs parses the arguments after the program name. An unknown flag, or
// install and uninstall together, is an error whose text starts with "usage:".
func parseArgs(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("efemon", flag.ContinueOnError)
	var discard strings.Builder
	fs.SetOutput(&discard) // the usage text is ours, not flag's
	fs.BoolVar(&o.Version, "version", false, "")
	fs.BoolVar(&o.NoBrowser, "no-browser", false, "")
	fs.BoolVar(&o.Service, "service", false, "")
	fs.BoolVar(&o.Install, "install-service", false, "")
	fs.BoolVar(&o.Uninstall, "uninstall-service", false, "")
	fs.BoolVar(&o.Status, "service-status", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return options{}, fmt.Errorf("usage: %s", usage())
	}
	if o.Install && o.Uninstall {
		return options{}, fmt.Errorf("usage: --install-service and --uninstall-service exclude each other\n%s", usage())
	}
	if o.Service {
		o.NoBrowser = true // at boot there is nobody to open a browser for
	}
	return o, nil
}

func usage() string {
	return `efemon [--no-browser] [--service]
       efemon --version
       efemon --install-service | --uninstall-service | --service-status   (Linux, root)

  --version            print the version and exit
  --no-browser         start without opening the dashboard in a browser
  --service            service mode: no browser; the tray icon attaches to the
                       desktop session when one appears; quit/restart via systemctl
  --install-service    copy the binary to /opt/efemon, write and enable the systemd unit
  --uninstall-service  stop, disable and remove the unit (data in /opt/efemon is kept)
  --service-status     print installed/active/path; exit 0 when installed and active`
}

// runServiceCommand runs --install-service / --uninstall-service /
// --service-status and exits; it returns false when none of them was asked.
// It runs before the log file, the DB or the listener exist: these commands
// act on the installation, not on a running monitor.
func runServiceCommand(o options) bool {
	switch {
	case o.Install:
		if err := installService(false); err != nil {
			fmt.Fprintln(os.Stderr, "install failed:", err)
			os.Exit(1)
		}
		fmt.Println("efemon installed and started as a systemd service (efemon.service); data in /opt/efemon.")
		fmt.Println("The tray icon appears when a desktop session is logged in. Remove with: efemon --uninstall-service")
		if !serviceStatus().Active {
			fmt.Println("Note: the unit is not active yet — another instance is probably holding the port.")
			fmt.Println("Stop the manual instance; the service retries on its own.")
		}
	case o.Uninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall failed:", err)
			os.Exit(1)
		}
		fmt.Println("efemon.service removed. /opt/efemon (database, .env with your keys) is kept;")
		fmt.Println("to delete it as well: rm -rf /opt/efemon")
	case o.Status:
		st := serviceStatus()
		if !st.Supported {
			fmt.Println("not supported on this OS")
			os.Exit(1)
		}
		fmt.Printf("installed=%t active=%t path=%s\n", st.Installed, st.Active, st.Path)
		if !(st.Installed && st.Active) {
			os.Exit(1)
		}
	default:
		return false
	}
	os.Exit(0)
	return true
}
