package main

import (
	"strings"
	"testing"
)

func TestSensitiveEnv(t *testing.T) {
	env := []string{
		"HOME=/home/efe", "PATH=/usr/bin", "SECRET_TOKEN=abc", // never shown
		"LD_PRELOAD=/tmp/.x/libhook.so",
		"http_proxy=http://alice:s3cret@proxy.corp:3128",
		"NODE_OPTIONS=--require /tmp/evil.js",
		"HTTPS_PROXY=", // empty: not set in any meaningful sense
		"PYTHONPATH=" + strings.Repeat("a", 150),
	}
	got := sensitiveEnv(env)
	if len(got) != 4 {
		t.Fatalf("got %d entries: %v", len(got), got)
	}
	if got[0] != "LD_PRELOAD=/tmp/.x/libhook.so" {
		t.Errorf("first = %q", got[0])
	}
	if got[1] != "http_proxy=http://***@proxy.corp:3128" {
		t.Errorf("proxy credentials not masked: %q", got[1])
	}
	if !strings.HasSuffix(got[3], "…") || len([]rune(got[3])) > 100+len("PYTHONPATH=")+1 {
		t.Errorf("long value not truncated: %q", got[3])
	}
	for _, e := range got {
		if strings.HasPrefix(e, "SECRET_TOKEN") || strings.HasPrefix(e, "HOME") {
			t.Errorf("non-sensitive variable leaked: %q", e)
		}
	}
}

func TestParseCgroup(t *testing.T) {
	for name, tc := range map[string]struct{ in, container, unit string }{
		"system service": {"0::/system.slice/nginx.service\n", "", "nginx.service"},
		"user app": {"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole-1234.scope\n",
			"", "app-org.kde.konsole-1234.scope"},
		"docker": {"0::/system.slice/docker-3f2a1b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4.scope\n",
			"docker:3f2a1b4c5d6e", ""},
		"podman": {"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd.scope/container\n",
			"libpod:abcdefabcdef", ""},
		"kubernetes": {"0::/kubepods/burstable/pod1234/cri-containerd-0123456789abcdef0123456789abcdef.scope\n",
			"cri-containerd:0123456789ab", ""},
		"cgroup v1 lines": {"12:pids:/system.slice/sshd.service\n1:name=systemd:/system.slice/sshd.service\n", "", "sshd.service"},
		"init":            {"0::/init.scope\n", "", ""},
		"escaped unit name": {"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-google\\x2dchrome@4631f9.service\n",
			"", "app-google-chrome@4631f9.service"},
		"session only": {"0::/user.slice/user-1000.slice/session-3.scope\n", "", ""},
		"empty":        {"", "", ""},
	} {
		c, u := parseCgroup(tc.in)
		if c != tc.container || u != tc.unit {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", name, c, u, tc.container, tc.unit)
		}
	}
}

func TestMaskURLCreds(t *testing.T) {
	for in, want := range map[string]string{
		"http://u:p@h:1":  "http://***@h:1",
		"socks5://h:1080": "socks5://h:1080",
		"/tmp/x.so":       "/tmp/x.so",
		"http://u@h/":     "http://***@h/",
	} {
		if got := maskURLCreds(in); got != want {
			t.Errorf("maskURLCreds(%q) = %q, want %q", in, got, want)
		}
	}
}
