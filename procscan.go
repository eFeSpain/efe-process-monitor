package main

import (
	"path"
	"strings"
)

// What a process is touching: sensitive files it holds open, and executable
// memory that did not come from a proper file. Both are read on Linux (see
// procscan_linux.go); the parsers here are pure and tested.
//
// Precision is the whole design. "Reads a file malware also likes" would be
// the path-signal mistake again, so every category has its expected readers —
// the browser owns its own profile, ssh owns its keys, the compositor owns the
// input devices — and only a *foreign* process holding the file is reported.

// fileCategory groups sensitive paths and names their legitimate readers.
type fileCategory struct {
	key     string // short id, used in the UI item and in tests
	scores  bool   // false: listed for context (camera/mic), never scored
	match   func(lower, base string) bool
	readers map[string]bool // process base names (lowercase) expected to hold these
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

var browsers2 = set("chrome", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave",
	"brave-browser", "msedge", "microsoft-edge", "firefox", "firefox-bin", "firefox-esr", "librewolf",
	"vivaldi", "vivaldi-bin", "opera", "thorium", "epiphany", "waterfox", "zen", "zen-bin", "floorp")

// bulkReaders touch everything by trade: backup and sync tools. They are
// accepted for every file category.
var bulkReaders = set("rsync", "restic", "borg", "duplicity", "tar", "rclone", "cp", "syncthing", "nextcloud",
	"dropbox", "megasync", "insync", "timeshift", "deja-dup", "kbackup", "kup", "kup-daemon", "baloo_file",
	"baloo_file_extractor", "tracker-miner-fs-3", "updatedb", "plocate-build", "clamd", "clamscan", "freshclam")

var fileCategories = []fileCategory{
	{"browser", true, func(l, b string) bool {
		switch b {
		case "login data", "cookies", "web data", "local state", "key4.db", "key3.db", "logins.json",
			"cookies.sqlite", "cert9.db", "signons.sqlite", "login data for account":
			return true
		}
		return false
	}, browsers2},
	{"ssh", true, func(l, b string) bool {
		return strings.Contains(l, "/.ssh/") && (strings.HasPrefix(b, "id_") || b == "authorized_keys" || b == "config")
	}, set("ssh", "sshd", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp", "git", "git-remote-https",
		"gpg-agent", "keepassxc", "1password", "bitwarden", "dropbear", "mosh", "mosh-client", "ansible", "ansible-playbook")},
	{"system", true, func(l, b string) bool {
		return l == "/etc/shadow" || l == "/etc/gshadow" || l == "/etc/sudoers" || strings.HasPrefix(l, "/etc/sudoers.d/")
	}, set("sudo", "su", "login", "sshd", "passwd", "chpasswd", "unix_chkpwd", "kcheckpass", "kscreenlocker_greet",
		"polkitd", "polkit-agent-helper-1", "gdm-session-worker", "lightdm", "sddm-helper", "cron", "crond", "atd",
		"systemd", "systemd-logind", "systemd-userwork", "visudo", "pwck", "grpck", "useradd", "usermod", "userdel")},
	{"keyring", true, func(l, b string) bool {
		return strings.HasSuffix(b, ".kdbx") || strings.HasSuffix(b, ".keyring") || strings.HasSuffix(b, ".kwl") ||
			strings.Contains(l, "/kwalletd/") || strings.Contains(l, "/share/keyrings/")
	}, set("gnome-keyring-daemon", "kwalletd5", "kwalletd6", "kwalletd", "keepassxc", "keepass", "keepassdx",
		"secret-tool", "seahorse", "bitwarden", "1password", "kwalletmanager5", "kwalletmanager")},
	{"wallet", true, func(l, b string) bool {
		return b == "wallet.dat" || strings.Contains(l, "/.electrum/") || strings.Contains(l, "/.bitcoin/") ||
			strings.Contains(l, "/.monero/") || strings.Contains(l, "/.ethereum/keystore/")
	}, set("bitcoind", "bitcoin-qt", "electrum", "monerod", "monero-wallet-cli", "monero-wallet-gui", "geth",
		"litecoind", "dogecoind", "exodus", "sparrow", "wasabi", "ledger-live")},
	{"input", true, func(l, b string) bool {
		return strings.HasPrefix(l, "/dev/input/")
	}, set("xorg", "x", "xwayland", "kwin_wayland", "kwin_x11", "mutter", "gnome-shell", "sway", "hyprland", "weston",
		"labwc", "wayfire", "river", "cage", "niri", "systemd-logind", "libinput", "evtest", "steam", "steamwebhelper",
		"solaar", "ydotool", "ydotoold", "xdotool", "dotool", "input-remapper-service", "input-remapper-control", "keyd",
		"kanata", "evremap", "touchegg", "fusuma", "gamescope", "retroarch", "emulationstation", "upower", "sddm",
		"gdm", "lightdm", "plymouthd", "sunshine", "moonlight", "openrgb", "piper", "ratbagd", "libratbag", "antimicrox",
		"joystickwake", "kded5", "kded6", "gnome-settings-daemon", "gsd-power", "gsd-media-keys", "acpid", "triggerhappy")},
	{"media", false, func(l, b string) bool {
		return strings.HasPrefix(l, "/dev/video") || (strings.HasPrefix(l, "/dev/snd/pcm") && strings.HasSuffix(l, "c"))
	}, set("pipewire", "pipewire-pulse", "wireplumber", "pulseaudio", "jackd", "pipewire-media-session", "obs",
		"zoom", "teams", "skype", "discord", "cheese", "guvcview", "ffmpeg", "vlc", "mpv", "gst-launch-1.0",
		"webcamoid", "kamoso", "snapshot", "cameractrls", "v4l2-ctl", "alsactl", "arecord")},
}

// sensitiveOpenFiles classifies a process's open files. It returns the items
// held by a process that is not an expected reader ("category: path"), the
// number of those that score, and the camera/microphone items listed for
// context only.
func sensitiveOpenFiles(procName string, files []string) (flagged []string, scored int, media []string) {
	me := procBase(procName)
	if bulkReaders[me] {
		return nil, 0, nil
	}
	seen := map[string]bool{}
	for _, f := range files {
		l := strings.ToLower(f)
		b := path.Base(l)
		for _, c := range fileCategories {
			if !c.match(l, b) || c.readers[me] {
				continue
			}
			item := c.key + ": " + f
			if seen[item] {
				break
			}
			seen[item] = true
			if c.scores {
				flagged = append(flagged, item)
				scored++
			} else {
				media = append(media, item)
			}
			break
		}
	}
	return flagged, scored, media
}

// systemLibDirs are where a "(deleted)" executable mapping is the ordinary
// aftermath of a package upgrade: the library on disk was replaced while the
// process kept the old one. Anywhere else, a deleted file still executing is
// a dropper that cleaned up after itself.
var systemLibDirs = []string{"/usr/lib", "/lib", "/usr/lib64", "/lib64", "/usr/libexec", "/usr/local/lib",
	"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt/", "/snap/", "/var/lib/flatpak/", "/nix/store/",
	"/usr/share/", "/var/lib/snapd/"}

// anomalousExecMaps scans /proc/<pid>/maps for executable regions backed by
// something that should never be executed from: a memfd, a staging directory,
// or a file deleted outside the system library tree. Anonymous executable
// regions are ignored on purpose — every JIT (browsers, Java, node, .NET)
// creates them, and flagging them would bury the real hits.
func anomalousExecMaps(maps string) []string {
	var out []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(maps, "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 || len(f[1]) < 3 || f[1][2] != 'x' {
			continue // not executable, or no path (anonymous)
		}
		p := strings.Join(f[5:], " ")
		l := strings.ToLower(p)
		var why string
		switch {
		case strings.HasPrefix(l, "/memfd:") || strings.HasPrefix(l, "memfd:"):
			why = "memfd"
		case strings.HasPrefix(l, "/dev/shm/") || strings.HasPrefix(l, "/tmp/") || strings.HasPrefix(l, "/var/tmp/"):
			why = "staging"
		case strings.HasSuffix(l, " (deleted)") && !underAny(l, systemLibDirs):
			why = "deleted"
		default:
			continue
		}
		item := why + ": " + p + " (" + f[1] + ")"
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func underAny(p string, prefixes []string) bool {
	for _, d := range prefixes {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
