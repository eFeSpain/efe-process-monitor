package main

import (
	"strings"
	"testing"
)

func TestSensitiveOpenFiles(t *testing.T) {
	files := []string{
		"/home/efe/.config/google-chrome/Default/Login Data",
		"/home/efe/.config/google-chrome/Default/Cookies",
		"/home/efe/.ssh/id_ed25519",
		"/home/efe/.ssh/known_hosts", // not a key
		"/etc/shadow",
		"/home/efe/Documents/vault.kdbx",
		"/dev/input/event3",
		"/dev/video0",
		"/dev/snd/pcmC0D0c", // capture
		"/dev/snd/pcmC0D0p", // playback: not capture
		"/usr/lib/libc.so.6",
		"/home/efe/notes.txt",
	}
	// An unknown process holding all of it: every scored category fires once
	// per file, camera and mic are context.
	flagged, scored, media := sensitiveOpenFiles("svc", files)
	if scored != 6 || len(flagged) != 6 {
		t.Errorf("foreign process: scored=%d flagged=%v", scored, flagged)
	}
	for _, want := range []string{"browser: ", "ssh: /home/efe/.ssh/id_ed25519", "system: /etc/shadow", "keyring: ", "input: /dev/input/event3"} {
		if !strings.Contains(strings.Join(flagged, "\n"), want) {
			t.Errorf("missing %q in %v", want, flagged)
		}
	}
	if len(media) != 2 {
		t.Errorf("media = %v, want camera + mic capture", media)
	}
	// Expected readers are not reported for their own category, but still for others.
	flagged, scored, _ = sensitiveOpenFiles("chrome", files)
	if strings.Contains(strings.Join(flagged, ""), "browser:") || scored != 4 {
		t.Errorf("chrome reading its own profile must not be flagged; got %d %v", scored, flagged)
	}
	flagged, _, _ = sensitiveOpenFiles("ssh", []string{"/home/efe/.ssh/id_rsa"})
	if len(flagged) != 0 {
		t.Errorf("ssh reading its key: %v", flagged)
	}
	flagged, _, media = sensitiveOpenFiles("/usr/bin/pipewire", []string{"/dev/snd/pcmC0D0c"})
	if len(flagged) != 0 || len(media) != 0 {
		t.Errorf("sound server with the mic: %v %v", flagged, media)
	}
	// Backup tools read everything; that is their job.
	flagged, scored, _ = sensitiveOpenFiles("restic", files)
	if scored != 0 || len(flagged) != 0 {
		t.Errorf("bulk reader flagged: %v", flagged)
	}
}

func TestAnomalousExecMaps(t *testing.T) {
	maps := "" +
		"55d0c4a00000-55d0c4a20000 r-xp 00000000 08:01 1234 /usr/bin/python3.12\n" +
		"7f1a00000000-7f1a00020000 r-xp 00000000 08:01 5678 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)\n" + // upgrade: fine
		"7f1a10000000-7f1a10020000 r-xp 00000000 00:01 91 /memfd:payload (deleted)\n" +
		"7f1a20000000-7f1a20020000 r-xp 00000000 08:01 42 /tmp/.x/lib.so\n" +
		"7f1a30000000-7f1a30020000 rw-p 00000000 08:01 42 /tmp/.x/lib.so\n" + // data segment: not executable
		"7f1a40000000-7f1a40020000 r-xp 00000000 08:01 77 /home/efe/dl/loader.so (deleted)\n" +
		"7f1a50000000-7f1a50100000 rwxp 00000000 00:00 0\n" + // anonymous JIT: ignored
		"7f1a60000000-7f1a60020000 r-xp 00000000 08:01 42 /dev/shm/x\n" +
		"7f1a60000000-7f1a60020000 r-xp 00000000 08:01 42 /dev/shm/x\n" // duplicate line
	got := anomalousExecMaps(maps)
	want := []string{
		"memfd: /memfd:payload (deleted) (r-xp)",
		"staging: /tmp/.x/lib.so (r-xp)",
		"deleted: /home/efe/dl/loader.so (deleted) (r-xp)",
		"staging: /dev/shm/x (r-xp)",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if anomalousExecMaps("") != nil {
		t.Error("empty maps must yield nothing")
	}
}

// Both signals score on their own, at the weights that put a lone hit in the
// "notable" band and a hit plus a staging path in "suspicious".
func TestAccessAndExecMapScore(t *testing.T) {
	base := Conn{VT: "NOT_IN_VT", RemoteIP: "8.8.8.8", Enrich: &Enrichment{},
		Sig: Signature{Status: "Packaged", Trusted: true}}
	c := base
	c.Details = &ProcDetails{CredFiles: 2, SensitiveFiles: []string{"browser: x", "ssh: y"}}
	if s := threatScore(&c); s != int(wCredAccess) || !strings.Contains(c.Breakdown, "credenciales") {
		t.Errorf("credential access: %d %q", s, c.Breakdown)
	}
	c = base
	c.Details = &ProcDetails{ExecAnomalies: []string{"memfd: /memfd:x (r-xp)"}}
	if s := threatScore(&c); s != int(wExecAnomaly) {
		t.Errorf("exec anomaly: %d %q", s, c.Breakdown)
	}
	c.Suspicious = true
	if s := threatScore(&c); !suspicious.contains(s) {
		t.Errorf("exec anomaly from a staging path should be suspicious, got %d", s)
	}
}

// Every Electron application — VS Code, Slack, Discord, Signal — keeps files
// called Cookies and Local State in its own directory, and holds them open.
// That is the application using its own store, not credential access; with
// the local signals alerting live it raised a red alert for the editor at
// every start. What the signal is about is a *browser's* store in the hands
// of something that is not a browser.
func TestOwnElectronStoreIsNotCredentialAccess(t *testing.T) {
	for _, c := range []struct {
		proc  string
		files []string
		want  int
	}{
		{"code", []string{"/home/efe/.config/Code/Cookies", "/home/efe/.config/Code/Local State"}, 0},
		{"slack", []string{"/home/x/.config/Slack/Cookies", "/home/x/.config/Slack/Local State"}, 0},
		{"signal-desktop", []string{"/home/x/.config/Signal/Cookies"}, 0},
		{"Discord", []string{"/home/x/.config/discord/Cookies", "/home/x/.config/discord/Web Data"}, 0},

		// A browser's store read by something else is still the signal…
		{"python3", []string{"/home/x/.config/google-chrome/Default/Cookies", "/home/x/.config/google-chrome/Default/Login Data"}, 2},
		{"code", []string{"/home/x/.config/chromium/Default/Login Data"}, 1},
		{"stealer", []string{"/home/x/.mozilla/firefox/ab12.default-release/logins.json", "/home/x/.mozilla/firefox/ab12.default-release/key4.db"}, 2},
		{"stealer", []string{"/home/x/snap/firefox/common/.mozilla/firefox/p/cookies.sqlite"}, 1},
		{"stealer", []string{"/home/x/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default/Login Data"}, 1},
		{"stealer", []string{"/home/x/.config/microsoft-edge/Default/Cookies"}, 1},
		{"stealer", []string{"/home/x/.thunderbird/ab12.default/logins.json"}, 1},
		{"stealer", []string{`C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\Login Data`}, 1},

		// …and a browser (or the mail client) reading it is not.
		{"chrome", []string{"/home/x/.config/google-chrome/Default/Cookies"}, 0},
		{"firefox", []string{"/home/x/.config/google-chrome/Default/Login Data"}, 0}, // importing from another browser
		{"thunderbird", []string{"/home/x/.thunderbird/ab12.default/logins.json"}, 0},
	} {
		flagged, scored, _ := sensitiveOpenFiles(c.proc, c.files)
		if scored != c.want {
			t.Errorf("%s holding %v: %d flagged %v, want %d", c.proc, c.files, scored, flagged, c.want)
		}
	}
}

// Seen as root on a KDE desktop: plasmashell raised "executable memory from
// a memfd" at every start. The Qt QML engine keeps its JIT output in a memfd
// called JITCode:QtQml, and Mesa its generated code in one called
// /.glXXXXXX — so does every QML application and every GL client. A memfd is
// still what fileless malware executes from; what a named JIT maps is not
// that.
func TestJITMemfdsAreNotAnomalous(t *testing.T) {
	maps := strings.Join([]string{
		"7f10a0000000-7f10a0010000 r-xp 00000000 00:01 2049 /memfd:JITCode:QtQml (deleted)",
		"7f10a0010000-7f10a0020000 rw-p 00000000 00:01 2049 /memfd:JITCode:QtQml (deleted)",
		"7f10b0000000-7f10b0001000 r-xp 00000000 00:01 2050 /memfd:/.glXXXXXX (deleted)",
		"7f10c0000000-7f10c0001000 r-xp 00000000 00:01 2051 /memfd:libffi (deleted)",
		"7f10d0000000-7f10d0001000 r-xp 00000000 00:01 2052 /memfd:doublemapper (deleted)",
	}, "\n")
	if got := anomalousExecMaps(maps); len(got) != 0 {
		t.Errorf("known JIT memfds were flagged: %v", got)
	}
	// Anything else in a memfd is still the signal, including a name that
	// merely starts like a JIT's.
	for _, name := range []string{"payload", "JITCode:QtQmlx", "x/.glXXXXXX", "", "libffi2"} {
		line := "7f10e0000000-7f10e0001000 r-xp 00000000 00:01 2053 /memfd:" + name + " (deleted)"
		if got := anomalousExecMaps(line); len(got) != 1 || !strings.HasPrefix(got[0], "memfd: ") {
			t.Errorf("memfd %q: %v, want it flagged", name, got)
		}
	}
}
