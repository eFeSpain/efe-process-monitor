//go:build linux

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Desktop interaction when running as root.
//
// Kill and firewall need root, so the tool is launched with sudo — and sudo's
// env_reset strips the graphical session out of the environment: no
// WAYLAND_DISPLAY, no XDG_RUNTIME_DIR, no DBUS_SESSION_BUS_ADDRESS. Three
// things stop working at once, each for that reason: xdg-open opens nothing,
// notify-send has no bus to talk to, and the tray icon needs a
// StatusNotifierWatcher on the *user's* session bus — which dbus-daemon only
// lets the owning uid onto ("the default is to allow connections from the same
// user ID that owns the dbus-daemon process", dbus-daemon(1)), so root cannot
// simply borrow the address.
//
// The fix is to do those three things as the user who logged in, not as root:
// the browser and notify-send are spawned with the user's credentials and the
// environment of their session (read from a process of theirs, since the
// variables are gone from ours), and the tray icon lives in a helper copy of
// this binary run the same way. The helper gets the dashboard URL — token
// included — over stdin, never argv, and tells the parent over stdout when
// "Quit" is clicked. Nothing privileged crosses that boundary: the helper only
// opens a browser and relays a click.

// desktopSession is the logged-in user's graphical session, as seen from root.
type desktopSession struct {
	uid, gid uint32
	name     string
	env      []string
}

var (
	desktopOnce sync.Once
	desktopSess *desktopSession
)

// desktopUser returns the session to hand desktop work to, or nil when we are
// not root or no session can be identified. Under sudo it is resolved once; in
// service mode it is whatever the session watcher currently holds — the
// service starts before anyone logs in, and the user may log out and in again.
func desktopUser() *desktopSession {
	if serviceMode && watcher != nil {
		return watcher.session()
	}
	desktopOnce.Do(func() {
		if os.Geteuid() != 0 {
			return
		}
		for _, uid := range desktopUserCandidates(os.Getenv, runUsers()) {
			if s := sessionFor(uid); s != nil {
				desktopSess = s
				return
			}
		}
	})
	return desktopSess
}

// runUsers lists the uids with a session bus under /run/user.
func runUsers() []string {
	var out []string
	if ents, err := os.ReadDir("/run/user"); err == nil {
		for _, e := range ents {
			if _, err := os.Stat(filepath.Join("/run/user", e.Name(), "bus")); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

// desktopSessionName is the user whose session the desktop work goes to, for
// the banner; "" when there is none.
func desktopSessionName() string {
	if s := desktopUser(); s != nil {
		return s.name
	}
	return ""
}

// ── Session watcher (service mode) ──────────────────────────────────────────
//
// A service starts at boot, before any graphical session exists, and the user
// may log out and back in while it runs. The watcher polls for a session and
// spawns the tray helper when one appears: one helper per session, never two;
// when the helper exits (logout) it waits for the next session. A desktop that
// answers "notray" (GNOME without the extension) is remembered for as long as
// that session lasts, so the helper is not forked again every tick.

type sessionWatcher struct {
	mu       sync.Mutex
	current  *desktopSession
	done     <-chan struct{} // closes when the current helper exits
	notray   map[uint32]bool // uids whose session has no tray host
	probe    func() *desktopSession
	spawn    func(*desktopSession) (done <-chan struct{}, ok bool)
	interval time.Duration
	onAttach func(*desktopSession)
	onDetach func(*desktopSession)
}

// watcher is the service-mode watcher; nil under sudo.
var watcher *sessionWatcher

// tick is one poll step.
func (w *sessionWatcher) tick() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		select {
		case <-w.done: // the helper is gone: the session ended (or it was killed)
			s := w.current
			w.current, w.done = nil, nil
			if w.onDetach != nil {
				w.onDetach(s)
			}
		default:
		}
		return
	}
	s := w.probe()
	if s == nil {
		w.notray = nil // no session: forget what the last one could not show
		return
	}
	if w.notray[s.uid] {
		return
	}
	done, ok := w.spawn(s)
	if !ok {
		if w.notray == nil {
			w.notray = map[uint32]bool{}
		}
		w.notray[s.uid] = true
		return
	}
	w.current, w.done = s, done
	if w.onAttach != nil {
		w.onAttach(s)
	}
}

// run polls until stop closes.
func (w *sessionWatcher) run(stop <-chan struct{}) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			w.tick()
		}
	}
}

func (w *sessionWatcher) session() *desktopSession {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.current
}

// desktopUserCandidates lists the uids to try, in order. Pure, so the choice is
// testable without being root.
func desktopUserCandidates(getenv func(string) string, runUsers []string) []string {
	var out []string
	for _, k := range []string{"SUDO_UID", "PKEXEC_UID"} {
		if v := getenv(k); v != "" && v != "0" {
			out = append(out, v)
		}
	}
	if len(out) > 0 {
		return out
	}
	// No sudo/pkexec (su -, a service): if exactly one logged-in user has a
	// session bus, that is the desktop we are on. Two or more is a guess we
	// don't make.
	var found []string
	for _, u := range runUsers {
		if u != "0" {
			found = append(found, u)
		}
	}
	if len(found) == 1 {
		return found
	}
	return nil
}

// sessionEnvKeys are the variables a graphical child needs from the user's
// session. Everything else (and in particular anything sudo set) is dropped.
var sessionEnvKeys = []string{
	"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
	"XDG_CURRENT_DESKTOP", "DESKTOP_SESSION", "DBUS_SESSION_BUS_ADDRESS",
	"HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "PATH", "BROWSER",
}

// sessionEnvFrom picks the whitelisted variables out of a /proc/<pid>/environ
// blob. Pure, for the tests.
func sessionEnvFrom(environ []byte) []string {
	var out []string
	for _, kv := range strings.Split(string(environ), "\x00") {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		for _, want := range sessionEnvKeys {
			if k == want {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

// sessionFor builds the session for a uid: credentials from the account
// database, environment from a process of theirs that has a display. Root can
// read any /proc/<pid>/environ; the scan is one-off at startup.
func sessionFor(uidStr string) *desktopSession {
	u, err := user.LookupId(uidStr)
	if err != nil {
		return nil
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return nil
	}
	s := &desktopSession{uid: uint32(uid), gid: uint32(gid), name: u.Username}

	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fi, err := os.Stat("/proc/" + e.Name())
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || uint64(st.Uid) != uid {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/environ") // #nosec G304 -- /proc scan, pid from ReadDir
		if err != nil {
			continue
		}
		env := sessionEnvFrom(b)
		if hasKey(env, "WAYLAND_DISPLAY") || hasKey(env, "DISPLAY") {
			s.env = env
			break
		}
	}
	if s.env == nil {
		return nil // the user is logged in on a console only: nothing to show a tray on
	}
	// Defaults for what a minimal session may not export.
	for k, v := range map[string]string{
		"HOME": u.HomeDir, "USER": u.Username, "LOGNAME": u.Username,
		"XDG_RUNTIME_DIR":          "/run/user/" + u.Uid,
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + u.Uid + "/bus",
		"PATH":                     "/usr/local/bin:/usr/bin:/bin",
	} {
		if !hasKey(s.env, k) {
			s.env = append(s.env, k+"="+v)
		}
	}
	return s
}

func hasKey(env []string, key string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			return true
		}
	}
	return false
}

// runAsDesktopUser makes cmd run with the logged-in user's credentials and
// session environment when we are root and that user is known. Returns
// whether it did; otherwise cmd is left to run as we are.
func runAsDesktopUser(cmd *exec.Cmd) bool { return runAsDesktopUserSession(cmd, desktopUser()) }

// ── Tray helper ──────────────────────────────────────────────────────────────

const trayHelperFlag = "--tray-helper"

// trayHelperMain is the entry point of the helper copy. It runs before anything
// else in main(): no log file, no database, no listener — it only shows the
// tray icon in the user's session and relays two things. Protocol, one line
// each: stdin carries the dashboard URL (token included); stdout says "ready"
// or "notray" once, then "quit" if the operator clicks Quit.
func trayHelperMain() bool {
	if len(os.Args) < 2 || os.Args[1] != trayHelperFlag {
		return false
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	url := strings.TrimSpace(line)
	if err != nil && url == "" {
		return true
	}
	if !hasTraySupport() {
		fmt.Println("notray")
		return true
	}
	fmt.Println("ready")
	// The helper has a clean environment: whether the parent is a service
	// travels as a second argument, and only changes the Quit label.
	runTray(func() { openBrowser(url) }, func() { fmt.Println("quit") }, len(os.Args) > 2 && os.Args[2] == "service")
	return true
}

// spawnTrayHelper starts the helper as the desktop user and waits for it to
// report. ok is true when the icon is up and done closes when the helper exits
// (logout, or killed); ok false means "no tray on this desktop" or the helper
// could not run, and the caller falls back to headless.
func spawnTrayHelper(url string, s *desktopSession) (done <-chan struct{}, ok bool) {
	exe, err := os.Executable()
	if err != nil {
		return nil, false
	}
	args := []string{trayHelperFlag}
	if serviceMode {
		args = append(args, "service")
	}
	cmd := command(exe, args...)
	if !runAsDesktopUserSession(cmd, s) {
		return nil, false
	}
	// Die with the parent: an orphaned icon pointing at a dead server is worse
	// than no icon.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, false
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("[tray] no se pudo lanzar el helper como %s: %v", s.name, err)
		return nil, false
	}
	fmt.Fprintln(stdin, url)
	stdin.Close()

	first := make(chan string, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			select {
			case first <- l:
			default:
			}
			if l == "quit" {
				log.Println("[tray] detenido desde el icono de bandeja")
				if serviceMode {
					// Stop the unit rather than just exiting: systemd would
					// otherwise see a clean exit and leave it stopped only
					// until the next failure-less restart — stop is explicit.
					if err := serviceControl("stop"); err != nil {
						log.Printf("[service] %v", err)
					}
				}
				os.Exit(0)
			}
		}
		_ = cmd.Wait()
		log.Printf("[tray] el helper de bandeja (uid=%d) ha terminado", s.uid)
	}()
	select {
	case l := <-first:
		return exited, l == "ready"
	case <-time.After(5 * time.Second):
		log.Println("[tray] el helper de bandeja no respondió")
		return nil, false
	}
}

// runAsDesktopUserSession is runAsDesktopUser for an explicit session: the
// watcher spawns the helper for the session it just found, which is not yet
// the current one.
func runAsDesktopUserSession(cmd *exec.Cmd, s *desktopSession) bool {
	if s == nil {
		return false
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: s.uid, Gid: s.gid, NoSetGroups: true}
	cmd.Env = s.env
	return true
}
