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
