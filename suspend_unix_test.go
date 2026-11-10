//go:build !windows

package main

import (
	"encoding/json"
	"testing"
	"time"
)

// Suspend freezes a real process (it stops running; its memory stays) and
// resume lets it go on, and the monitor can tell which state it is in.
func TestSuspendAndResume(t *testing.T) {
	cmd := command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a child process: %v", err)
	}
	pid := int32(cmd.Process.Pid)
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	stoppedSoon := func(want bool) bool {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if procStopped(pid) == want {
				return true
			}
		}
		return false
	}
	if procStopped(pid) {
		t.Fatal("a running process is not suspended")
	}

	var out map[string]any
	json.Unmarshal(jsonPost(handleSuspend, "/api/suspend", `{"PID":`+itoa(int(pid))+`}`).Body.Bytes(), &out)
	if out["ok"] != true || out["suspended"] != true {
		t.Fatalf("suspend: %v", out)
	}
	if !stoppedSoon(true) {
		t.Fatal("the process is still running after suspend")
	}

	out = map[string]any{}
	json.Unmarshal(jsonPost(handleSuspend, "/api/suspend", `{"PID":`+itoa(int(pid))+`,"Resume":true}`).Body.Bytes(), &out)
	if out["ok"] != true || out["suspended"] != false {
		t.Fatalf("resume: %v", out)
	}
	if !stoppedSoon(false) {
		t.Fatal("the process is still frozen after resume")
	}
}
