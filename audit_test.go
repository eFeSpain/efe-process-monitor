package main

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUserHomesFrom(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"efe:x:1000:1000:efe:/home/efe:/bin/bash\n" +
		"guest:x:1001:1001::/home/guest:/bin/bash\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
		"svc:x:1002:1002::/home/efe:/bin/sh\n" + // shares a home: listed once
		"broken line\n"
	exists := func(p string) bool { return p != "/home/guest" }
	got := userHomesFrom(passwd, exists)
	want := "root=/root efe=/home/efe"
	var parts []string
	for _, u := range got {
		parts = append(parts, u.name+"="+u.home)
	}
	if strings.Join(parts, " ") != want {
		t.Errorf("homes = %q, want %q", strings.Join(parts, " "), want)
	}
}

func TestParseRegRunLines(t *testing.T) {
	out := "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n" +
		"    OneDrive    REG_SZ    \"C:\\Users\\efe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\r\n" +
		"    Updater    REG_SZ    powershell -w hidden -enc SQBFAFgA\r\n" +
		"    Dropper    REG_EXPAND_SZ    C:\\Users\\efe\\AppData\\Local\\Temp\\x.exe\r\n"
	entries, susp := parseRegRunLines(out)
	if len(entries) != 3 {
		t.Fatalf("entries = %v", entries)
	}
	if len(susp) != 2 || !strings.HasPrefix(susp[0], "Updater") || !strings.HasPrefix(susp[1], "Dropper") {
		t.Errorf("suspicious = %v", susp)
	}
}

func TestRegValueAndIFEO(t *testing.T) {
	if v := regValue("\r\nHKEY_LOCAL_MACHINE\\...\\Winlogon\r\n    Shell    REG_SZ    explorer.exe\r\n"); v != "explorer.exe" {
		t.Errorf("regValue = %q", v)
	}
	out := "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\r\n" +
		"    Debugger    REG_SZ    C:\\Windows\\System32\\cmd.exe\r\n\r\n" +
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\r\n"
	hits := parseIFEO(out)
	if len(hits) != 1 || hits[0] != `sethc.exe → C:\Windows\System32\cmd.exe` {
		t.Errorf("IFEO hits = %v", hits)
	}
}

func TestParseWinServices(t *testing.T) {
	out := "Spooler\tRunning\tC:\\Windows\\System32\\spoolsv.exe\n" +
		"Vendor Agent\tRunning\tC:\\Program Files\\Vendor\\agent.exe -svc\n" +
		"Good\tStopped\t\"C:\\Program Files\\Good\\good.exe\" -svc\n" +
		"Evil\tRunning\tC:\\Users\\efe\\AppData\\Roaming\\svc.exe\n" +
		"broken line\n"
	susp, unquoted := parseWinServices(out)
	if len(susp) != 1 || !strings.HasPrefix(susp[0], "Evil") {
		t.Errorf("suspicious = %v", susp)
	}
	if len(unquoted) != 1 || !strings.HasPrefix(unquoted[0], "Vendor Agent") {
		t.Errorf("unquoted = %v", unquoted)
	}
	for p, want := range map[string]bool{
		`C:\Windows\System32\svchost.exe -k netsvcs`: false,
		`C:\Program Files\X\x.exe`:                   true,
		`"C:\Program Files\X\x.exe" -a b`:            false,
		`C:\X\x.exe -flag with space`:                false, // the space is after the .exe
		"":                                           false,
	} {
		if got := unquotedServicePath(p); got != want {
			t.Errorf("unquotedServicePath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestParseSchtasksAndDrivers(t *testing.T) {
	sch := "\"HostName\",\"TaskName\",\"Next Run Time\"\n" +
		"\"PC\",\"\\Microsoft\\Windows\\Defrag\",\"N/A\",\"C:\\Windows\\system32\\defrag.exe\"\n" +
		"\"PC\",\"\\Updater\",\"N/A\",\"C:\\Users\\efe\\AppData\\Roaming\\u.exe\"\n"
	if got := parseSchtasksSuspicious(sch); len(got) != 1 || got[0] != `\Updater` {
		t.Errorf("schtasks = %v", got)
	}
	drv := "\"Module Name\",\"Display Name\",\"IsSigned\",\"Manufacturer\"\n" +
		"\"ACPI\",\"ACPI Driver\",\"TRUE\",\"Microsoft\"\n" +
		"\"evil\",\"Evil\",\"FALSE\",\"\"\n"
	if got := parseDriverQueryUnsigned(drv); len(got) != 1 || got[0] != "evil" {
		t.Errorf("drivers = %v", got)
	}
}

func TestParseListeningPorts(t *testing.T) {
	ss := "udp   UNCONN 0  0  0.0.0.0%lo:53   0.0.0.0:*\n" +
		"tcp   LISTEN 0  128  [::]:22   [::]:*\n" +
		"tcp   LISTEN 0  4096 127.0.0.1:5000 0.0.0.0:*\n"
	if got := parseListeningPorts(ss, false); len(got) != 3 || got[0] != 53 || got[1] != 22 || got[2] != 5000 {
		t.Errorf("ss ports = %v", got)
	}
	ns := "  TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234\n" +
		"  TCP    192.168.1.2:49712    1.2.3.4:443    ESTABLISHED    99\n" +
		"  UDP    0.0.0.0:5353    *:*    4321\n"
	if got := parseListeningPorts(ns, true); len(got) != 1 || got[0] != 135 {
		t.Errorf("netstat ports = %v", got)
	}
}

func TestSystemdExecAndSuspicious(t *testing.T) {
	unit := "[Unit]\nDescription=x\n[Service]\nExecStartPre=-/usr/bin/true\nExecStart=/tmp/.x/miner --pool a\nExecReload=/bin/kill -HUP $MAINPID\n"
	ex := parseSystemdExec(unit)
	if len(ex) != 3 || ex[1] != "/tmp/.x/miner --pool a" {
		t.Errorf("exec = %v", ex)
	}
	for cmd, want := range map[string]bool{
		"/tmp/.x/miner --pool a":        true,
		"-/home/efe/bin/agent":          true,
		"/usr/bin/true":                 false,
		"@/dev/shm/x argv0":             true,
		"/usr/local/bin/backup --daily": false,
		"":                              false,
	} {
		if got := suspiciousExecPath(cmd); got != want {
			t.Errorf("suspiciousExecPath(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestFirewallRuleCounts(t *testing.T) {
	nft := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n" +
		"\t\tct state established,related accept\n\t\ttcp dport 22 accept\n\t}\n}\n"
	if n := countNftRules(nft); n != 2 {
		t.Errorf("nft rules = %d, want 2", n)
	}
	if n := countNftRules(""); n != 0 {
		t.Errorf("empty ruleset = %d", n)
	}
	ipt := "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N DOCKER\n-A INPUT -i lo -j ACCEPT\n"
	if n := countIptablesRules(ipt); n != 1 {
		t.Errorf("iptables rules = %d, want 1", n)
	}
}

func TestCustomHostsLines(t *testing.T) {
	content := "127.0.0.1 localhost\n" +
		"127.0.1.1 hades hades.localdomain\n" +
		"::1 ip6-localhost ip6-loopback\n" +
		"ff02::1 ip6-allnodes\n" +
		"# 1.1.1.1 commented.out\n" +
		"1.2.3.4 login.bank.com # localhost\n" +
		"0.0.0.0 ads.example.com\n" +
		"not an entry\n"
	got := customHostsLines(content, "hades")
	if len(got) != 2 || got[0] != "1.2.3.4 login.bank.com" || got[1] != "0.0.0.0 ads.example.com" {
		t.Errorf("custom = %v", got)
	}
}

// The diff marks what earlier scans had not seen, within a window, and never
// on the first scan of a machine.
func TestAuditDiff(t *testing.T) {
	setupTestDB(t)
	first := []AuditCheck{{Key: "pw_run", Items: []string{"a → x", "b → y"}}}
	applyAuditDiff(first)
	if len(first[0].New) != 0 {
		t.Errorf("first scan must mark nothing new, got %v", first[0].New)
	}
	second := []AuditCheck{{Key: "pw_run", Items: []string{"a → x", "c → z"}}, {Key: "pl_cron", Items: []string{"root: @reboot /tmp/x"}}}
	applyAuditDiff(second)
	if len(second[0].New) != 1 || second[0].New[0] != "c → z" {
		t.Errorf("new Run item = %v", second[0].New)
	}
	if len(second[1].New) != 1 {
		t.Errorf("a whole new check's items are new: %v", second[1].New)
	}
	// Still new on the next scan (within the window), not "seen last time".
	third := []AuditCheck{{Key: "pw_run", Items: []string{"c → z"}}}
	applyAuditDiff(third)
	if len(third[0].New) != 1 {
		t.Errorf("item must stay new within %s, got %v", auditNewWindow, third[0].New)
	}
	// And old once the window has passed.
	db.Exec("UPDATE audit_seen SET first_seen = ?", float64(time.Now().Add(-2*auditNewWindow).UnixNano())/1e9)
	fourth := []AuditCheck{{Key: "pw_run", Items: []string{"c → z"}}}
	applyAuditDiff(fourth)
	if len(fourth[0].New) != 0 {
		t.Errorf("item older than the window must not be new: %v", fourth[0].New)
	}
}

func TestProcNetAndSocketInodes(t *testing.T) {
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123740 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0F01A8C0:C2A6 11AFB814:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 71798 1 0000000000000000 20 4 30 10 -1\n"
	got := parseProcNetInodes(tcp)
	if len(got) != 2 || got[0] != "123740" || got[1] != "71798" {
		t.Errorf("inodes = %v", got)
	}
	if socketInode("socket:[6731]") != "6731" || socketInode("pipe:[99]") != "" || socketInode("/dev/pts/3") != "" {
		t.Error("socketInode")
	}
}

func TestCronEnvAndDesktopExec(t *testing.T) {
	for ln, want := range map[string]bool{
		"SHELL=/bin/sh": true, "PATH=/usr/bin:/bin": true, "MAILTO=root": true,
		"17 * * * * root cd / && run-parts /etc/cron.hourly": false,
		"@reboot /tmp/x": false, "=x": false,
	} {
		if got := cronEnvLine(ln); got != want {
			t.Errorf("cronEnvLine(%q) = %v", ln, got)
		}
	}
	d := "[Desktop Entry]\nName=x\nExec=/home/efe/.cache/.x/agent --quiet\nType=Application\n"
	if got := desktopExec(d); got != "/home/efe/.cache/.x/agent --quiet" || !suspiciousExecPath(got) {
		t.Errorf("desktopExec = %q", got)
	}
}

func TestTaintAndKnownModules(t *testing.T) {
	if got := taintFlags(12288); got != "O E" {
		t.Errorf("taintFlags(12288) = %q, want \"O E\"", got)
	}
	if got := taintFlags(1 | 64); got != "P U" {
		t.Errorf("taintFlags(65) = %q", got)
	}
	if taintFlags(0) != "" {
		t.Error("taintFlags(0) should be empty")
	}
	mods := []string{"nvidia (OE)", "nvidia_drm (OE)", "vboxdrv (O)", "diamorphine (OE)"}
	if got := unknownModules(mods); len(got) != 1 || got[0] != "diamorphine (OE)" {
		t.Errorf("unknownModules = %v", got)
	}
}

func TestEnsureSbinPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	t.Setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
	ensureSbinPath()
	got := os.Getenv("PATH")
	for _, d := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(":"+got+":", ":"+d+":") {
			t.Errorf("%s missing from PATH %q", d, got)
		}
	}
	ensureSbinPath() // idempotent
	if strings.Count(got+":", "/usr/sbin:") != 1 || os.Getenv("PATH") != got {
		t.Errorf("PATH grew on a second call: %q", os.Getenv("PATH"))
	}
}

func TestSortBySeverity(t *testing.T) {
	in := []AuditCheck{{Key: "a", Status: "ok"}, {Key: "b", Status: "risk"}, {Key: "c", Status: "info"}, {Key: "d", Status: "warn"}, {Key: "e", Status: "risk"}}
	var keys []string
	for _, c := range sortBySeverity(in) {
		keys = append(keys, c.Key)
	}
	if got := strings.Join(keys, ""); got != "bedca" {
		t.Errorf("order = %q, want bedca (stable within a level)", got)
	}
}
