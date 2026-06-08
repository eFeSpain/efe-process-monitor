package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// AuditCheck is one finding of the machine audit.
type AuditCheck struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"` // ok | warn | risk | info
	Detail   string `json:"detail"`
}

// auditStrings holds every user-facing audit string per language.
var auditStrings = map[string]map[string]string{
	"es": {
		"found_prefix": "%d encontrado(s): ", "more": " … (+%d más)",
		"cat_proc": "Procesos", "cat_persist": "Persistencia", "cat_harden": "Hardening",
		"cat_rk":       "Rootkit (heurístico)",
		"p_suspath":    "Procesos desde rutas sospechosas (Temp/Downloads…)",
		"p_suspath_ok": "Ningún proceso corriendo desde rutas sospechosas.",
		"p_masq":       "Suplantación de procesos del sistema",
		"p_masq_ok":    "Procesos del sistema en sus rutas legítimas.",
		"p_deleted":    "Procesos con binario borrado en disco",
		"p_deleted_ok": "Ningún proceso con su binario eliminado del disco.",
		"pw_run_susp":  "Claves Run sospechosas",
		"pw_run":       "Claves de inicio (Run/RunOnce)", "pw_run_ok": "Sin entradas de autoarranque en Run.",
		"pw_startup": "Carpeta de inicio (Startup)", "pw_startup_ok": "Carpeta de inicio vacía.",
		"pw_tasks":    "Tareas programadas sospechosas",
		"pw_tasks_ok": "Sin tareas programadas apuntando a rutas sospechosas.",
		"pl_cron":     "Tareas cron", "pl_cron_ok": "Sin tareas cron.",
		"pl_rc":    "Líneas sospechosas en rc/.bashrc",
		"pl_rc_ok": "Sin descargas/reverse-shells en ficheros de arranque de shell.",
		"pl_auto":  "Autostart de escritorio", "pl_auto_ok": "Sin entradas de autostart.",
		"pl_systemd": "Unidades systemd de usuario", "pl_systemd_ok": "Sin unidades systemd de usuario.",
		"hw_fw": "Firewall de Windows", "fw_off": "%d perfil(es) con el firewall DESACTIVADO.",
		"fw_on": "Activo en todos los perfiles.", "fw_unknown": "No se pudo determinar.",
		"hw_def": "Defender (tiempo real)", "def_off": "Protección en tiempo real DESACTIVADA.",
		"def_on": "Activa. Edad de firmas: %s días.", "def_na": "No disponible (¿otro AV o sin permisos?).",
		"hw_rdp": "Escritorio remoto (RDP)", "rdp_on": "RDP está HABILITADO.", "rdp_off": "RDP deshabilitado.",
		"hw_admins": "Miembros de Administradores",
		"hosts":     "Fichero hosts", "hosts_unread": "No se pudo leer %s",
		"hosts_clean": "Sin entradas personalizadas.", "hosts_custom": "Fichero hosts (entradas personalizadas)",
		"hl_ufw": "Firewall (ufw)", "ufw_off": "ufw INACTIVO.", "ufw_on": "ufw activo.",
		"hl_fw": "Firewall", "ufw_na": "ufw no instalado (revisa iptables/nft manualmente).",
		"hl_ssh": "Configuración SSH", "ssh_ok": "SSH endurecido (sin root/password).",
		"hl_uid0": "Cuentas con UID 0 (además de root)", "uid0_ok": "Solo root tiene UID 0.",
		"rk_hidden": "Procesos ocultos (cross-view)", "rk_hidden_ok": "Sin discrepancias entre fuentes de procesos.",
		"rk_ports":    "Puertos a la escucha ocultos (cross-view)",
		"rk_ports_ok": "Sin discrepancias en puertos a la escucha.", "rk_ports_na": "No se pudo comparar con netstat/ss.",
		"rk_port_item": "%d (en netstat/ss, no en la API)",
		"rk_preload":   "/etc/ld.so.preload", "preload_bad": "Presente y no vacío (técnica de rootkit de usuario): %s",
		"preload_ok":  "Ausente o vacío.",
		"rk_tainted":  "Kernel tainted",
		"tainted_bad": "tainted=%s (módulo fuera de árbol/sin firma; puede ser legítimo: drivers propietarios)",
		"tainted_ok":  "tainted=0",
		"rk_promisc":  "Interfaces en modo promiscuo", "promisc_ok": "Ninguna interfaz en modo promiscuo.",
		"rk_drivers": "Drivers sin firma", "drivers_ok": "Todos los drivers están firmados.",
		"rk_proc_proc": "PID %d responde a señal pero no aparece en /proc",
		"rk_proc_only": "PID %d visible solo en %s", "src_api": "la API",
		// Nuevos checks Linux
		"hl_authkeys":     "Claves SSH autorizadas (~/.ssh/authorized_keys)",
		"authkeys_ok":     "Sin claves SSH autorizadas.",
		"hl_sudo":         "Entradas NOPASSWD en sudoers",
		"sudo_ok":         "Sin entradas NOPASSWD en sudoers.",
		"hl_suid":         "Binarios SUID/SGID en rutas peligrosas (/tmp, /home…)",
		"suid_ok":         "Sin binarios SUID/SGID en rutas peligrosas.",
		"hl_mac":          "Control de acceso obligatorio (AppArmor / SELinux)",
		"mac_aa_ok":       "AppArmor activo (%d perfiles cargados).",
		"mac_se_ok":       "SELinux activo en modo enforcing.",
		"mac_se_perm":     "SELinux en modo permissive (registra pero NO bloquea).",
		"mac_off":         "Ni AppArmor ni SELinux están activos.",
		"mac_na":          "AppArmor/SELinux no detectado en este sistema.",
		"hl_path_ww":      "Directorios del PATH escribibles por cualquier usuario",
		"path_ww_ok":      "Ningún directorio del PATH es world-writable.",
		"rk_env_preload":  "LD_PRELOAD en /etc/environment",
		"env_preload_bad": "LD_PRELOAD detectado en /etc/environment (inyección de biblioteca): %s",
		"rk_modules":      "Módulos del kernel fuera de árbol (out-of-tree / unsigned)",
		"modules_ok":      "Sin módulos fuera de árbol detectados.",
		"modules_na":      "No se pudo leer /sys/module.",
	},
	"en": {
		"found_prefix": "%d found: ", "more": " … (+%d more)",
		"cat_proc": "Processes", "cat_persist": "Persistence", "cat_harden": "Hardening",
		"cat_rk":       "Rootkit (heuristic)",
		"p_suspath":    "Processes from suspicious paths (Temp/Downloads…)",
		"p_suspath_ok": "No processes running from suspicious paths.",
		"p_masq":       "System process masquerading",
		"p_masq_ok":    "System processes in their legitimate paths.",
		"p_deleted":    "Processes whose binary was deleted from disk",
		"p_deleted_ok": "No process with its on-disk binary deleted.",
		"pw_run_susp":  "Suspicious Run keys",
		"pw_run":       "Startup keys (Run/RunOnce)", "pw_run_ok": "No autostart entries in Run.",
		"pw_startup": "Startup folder", "pw_startup_ok": "Startup folder empty.",
		"pw_tasks":    "Suspicious scheduled tasks",
		"pw_tasks_ok": "No scheduled tasks pointing to suspicious paths.",
		"pl_cron":     "Cron jobs", "pl_cron_ok": "No cron jobs.",
		"pl_rc":    "Suspicious lines in rc/.bashrc",
		"pl_rc_ok": "No downloads/reverse-shells in shell startup files.",
		"pl_auto":  "Desktop autostart", "pl_auto_ok": "No autostart entries.",
		"pl_systemd": "User systemd units", "pl_systemd_ok": "No user systemd units.",
		"hw_fw": "Windows Firewall", "fw_off": "%d profile(s) with the firewall DISABLED.",
		"fw_on": "Enabled on all profiles.", "fw_unknown": "Could not determine.",
		"hw_def": "Defender (real-time)", "def_off": "Real-time protection DISABLED.",
		"def_on": "Active. Signature age: %s days.", "def_na": "Unavailable (another AV or no permissions?).",
		"hw_rdp": "Remote Desktop (RDP)", "rdp_on": "RDP is ENABLED.", "rdp_off": "RDP disabled.",
		"hw_admins": "Administrators group members",
		"hosts":     "hosts file", "hosts_unread": "Could not read %s",
		"hosts_clean": "No custom entries.", "hosts_custom": "hosts file (custom entries)",
		"hl_ufw": "Firewall (ufw)", "ufw_off": "ufw INACTIVE.", "ufw_on": "ufw active.",
		"hl_fw": "Firewall", "ufw_na": "ufw not installed (check iptables/nft manually).",
		"hl_ssh": "SSH configuration", "ssh_ok": "SSH hardened (no root/password).",
		"hl_uid0": "UID 0 accounts (besides root)", "uid0_ok": "Only root has UID 0.",
		"rk_hidden": "Hidden processes (cross-view)", "rk_hidden_ok": "No discrepancies between process sources.",
		"rk_ports":    "Hidden listening ports (cross-view)",
		"rk_ports_ok": "No discrepancies in listening ports.", "rk_ports_na": "Could not compare with netstat/ss.",
		"rk_port_item": "%d (in netstat/ss, not in the API)",
		"rk_preload":   "/etc/ld.so.preload", "preload_bad": "Present and non-empty (user-mode rootkit technique): %s",
		"preload_ok":  "Absent or empty.",
		"rk_tainted":  "Kernel tainted",
		"tainted_bad": "tainted=%s (out-of-tree/unsigned module; may be legitimate: proprietary drivers)",
		"tainted_ok":  "tainted=0",
		"rk_promisc":  "Interfaces in promiscuous mode", "promisc_ok": "No interface in promiscuous mode.",
		"rk_drivers": "Unsigned drivers", "drivers_ok": "All drivers are signed.",
		"rk_proc_proc": "PID %d answers a signal but is absent from /proc",
		"rk_proc_only": "PID %d visible only in %s", "src_api": "the API",
		// New Linux checks
		"hl_authkeys":     "Authorized SSH keys (~/.ssh/authorized_keys)",
		"authkeys_ok":     "No authorized SSH keys.",
		"hl_sudo":         "NOPASSWD entries in sudoers",
		"sudo_ok":         "No NOPASSWD entries in sudoers.",
		"hl_suid":         "SUID/SGID binaries in dangerous paths (/tmp, /home…)",
		"suid_ok":         "No SUID/SGID binaries found in dangerous paths.",
		"hl_mac":          "Mandatory access control (AppArmor / SELinux)",
		"mac_aa_ok":       "AppArmor active (%d profiles loaded).",
		"mac_se_ok":       "SELinux active in enforcing mode.",
		"mac_se_perm":     "SELinux in permissive mode (logs but does NOT block).",
		"mac_off":         "Neither AppArmor nor SELinux is active.",
		"mac_na":          "AppArmor/SELinux not detected on this system.",
		"hl_path_ww":      "World-writable directories in PATH",
		"path_ww_ok":      "No world-writable directories in PATH.",
		"rk_env_preload":  "LD_PRELOAD in /etc/environment",
		"env_preload_bad": "LD_PRELOAD detected in /etc/environment (library injection technique): %s",
		"rk_modules":      "Out-of-tree / unsigned kernel modules",
		"modules_ok":      "No out-of-tree modules detected.",
		"modules_na":      "Could not read /sys/module.",
	},
}

// atr looks up an audit string for a language (falls back to Spanish).
func atr(lang, key string) string {
	if m, ok := auditStrings[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return auditStrings["es"][key]
}

var (
	auditMu    sync.Mutex
	auditCache = map[string][]AuditCheck{}
	auditAt    = map[string]time.Time{}
)

func auditCached(lang string, refresh bool) []AuditCheck {
	auditMu.Lock()
	defer auditMu.Unlock()
	if refresh || auditCache[lang] == nil || time.Since(auditAt[lang]) > 30*time.Second {
		auditCache[lang] = Audit(lang)
		auditAt[lang] = time.Now()
	}
	return auditCache[lang]
}

// Audit runs all checks for the current OS in the given language.
func Audit(lang string) []AuditCheck {
	var c []AuditCheck
	c = append(c, auditProcesses(lang)...)
	c = append(c, auditPersistence(lang)...)
	c = append(c, auditHardening(lang)...)
	c = append(c, auditRootkit(lang)...)
	return c
}

func runCmd(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, _ := commandContext(ctx, name, args...).Output()
	return string(out)
}

// finding builds one check from a list of offending items (cat/name/ok already translated).
func finding(lang, cat, name, status string, items []string, ok string) AuditCheck {
	if len(items) == 0 {
		return AuditCheck{cat, name, "ok", ok}
	}
	shown, extra := items, ""
	if len(shown) > 12 {
		shown = shown[:12]
		extra = fmt.Sprintf(atr(lang, "more"), len(items)-12)
	}
	return AuditCheck{cat, name, status,
		fmt.Sprintf(atr(lang, "found_prefix"), len(items)) + strings.Join(shown, " | ") + extra}
}

// ── Processes ────────────────────────────────────────────────────────────────

func auditProcesses(lang string) []AuditCheck {
	cat := atr(lang, "cat_proc")
	var susPath, masq, deleted []string
	sysNames := map[string]bool{
		"svchost.exe": true, "lsass.exe": true, "services.exe": true,
		"csrss.exe": true, "winlogon.exe": true, "smss.exe": true, "wininit.exe": true,
	}
	procs, _ := process.Processes()
	for _, p := range procs {
		name, _ := p.Name()
		exe, _ := p.Exe()
		if isSuspiciousPath(exe) {
			susPath = append(susPath, fmt.Sprintf("%s (pid %d) %s", name, p.Pid, exe))
		}
		if runtime.GOOS == "windows" && exe != "" && sysNames[strings.ToLower(name)] {
			le := strings.ToLower(exe)
			if !strings.Contains(le, `\windows\system32\`) && !strings.Contains(le, `\windows\syswow64\`) {
				masq = append(masq, fmt.Sprintf("%s (pid %d) %s", name, p.Pid, exe))
			}
		}
		if runtime.GOOS != "windows" {
			if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.Pid)); err == nil &&
				strings.Contains(link, "(deleted)") {
				deleted = append(deleted, fmt.Sprintf("%s (pid %d) %s", name, p.Pid, link))
			}
		}
	}
	out := []AuditCheck{
		finding(lang, cat, atr(lang, "p_suspath"), "risk", susPath, atr(lang, "p_suspath_ok")),
	}
	if runtime.GOOS == "windows" {
		out = append(out, finding(lang, cat, atr(lang, "p_masq"), "risk", masq, atr(lang, "p_masq_ok")))
	} else {
		out = append(out, finding(lang, cat, atr(lang, "p_deleted"), "risk", deleted, atr(lang, "p_deleted_ok")))
	}
	return out
}

// ── Persistence ──────────────────────────────────────────────────────────────

func auditPersistence(lang string) []AuditCheck {
	if runtime.GOOS == "windows" {
		return auditPersistenceWindows(lang)
	}
	return auditPersistenceLinux(lang)
}

func auditPersistenceWindows(lang string) []AuditCheck {
	cat := atr(lang, "cat_persist")
	var out []AuditCheck

	var runEntries, runSusp []string
	for _, hive := range []string{
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	} {
		for _, ln := range strings.Split(runCmd(8*time.Second, "reg", "query", hive), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "HKEY") {
				continue
			}
			if i := strings.Index(ln, "REG_"); i > 0 {
				name := strings.TrimSpace(ln[:i])
				val := ""
				if j := strings.Index(ln[i:], "    "); j >= 0 {
					val = strings.TrimSpace(ln[i+j:])
				}
				entry := name + " → " + val
				runEntries = append(runEntries, entry)
				lv := strings.ToLower(val)
				for _, sig := range []string{`\temp\`, `\downloads\`, "-enc", "-encodedcommand",
					"mshta", "frombase64string", "downloadstring", "-w hidden",
					"-windowstyle hidden", "iex(", "javascript:", "regsvr32 /s /n /u /i"} {
					if strings.Contains(lv, sig) {
						runSusp = append(runSusp, entry)
						break
					}
				}
			}
		}
	}
	if len(runSusp) > 0 {
		out = append(out, finding(lang, cat, atr(lang, "pw_run_susp"), "risk", runSusp, ""))
	} else {
		out = append(out, finding(lang, cat, atr(lang, "pw_run"), "info", runEntries, atr(lang, "pw_run_ok")))
	}

	var startup []string
	for _, d := range []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	} {
		if ents, err := os.ReadDir(d); err == nil {
			for _, e := range ents {
				if !e.IsDir() && !strings.EqualFold(e.Name(), "desktop.ini") {
					startup = append(startup, e.Name())
				}
			}
		}
	}
	out = append(out, finding(lang, cat, atr(lang, "pw_startup"), "warn", startup, atr(lang, "pw_startup_ok")))

	var tasks []string
	for _, ln := range strings.Split(runCmd(20*time.Second, "schtasks", "/query", "/v", "/fo", "csv"), "\n") {
		l := strings.ToLower(ln)
		if strings.Contains(l, `\temp\`) || strings.Contains(l, `\appdata\`) ||
			strings.Contains(l, "powershell -enc") || strings.Contains(l, "mshta") {
			if f := strings.Split(ln, ","); len(f) > 1 {
				tasks = append(tasks, strings.Trim(f[0], `"`))
			}
		}
	}
	out = append(out, finding(lang, cat, atr(lang, "pw_tasks"), "risk", tasks, atr(lang, "pw_tasks_ok")))
	return out
}

func auditPersistenceLinux(lang string) []AuditCheck {
	cat := atr(lang, "cat_persist")
	var out []AuditCheck

	var cron []string
	cronFiles := []string{"/etc/crontab"}
	for _, d := range []string{"/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"} {
		if ents, err := os.ReadDir(d); err == nil {
			for _, e := range ents {
				cronFiles = append(cronFiles, filepath.Join(d, e.Name()))
			}
		}
	}
	for _, f := range cronFiles {
		if b, err := os.ReadFile(f); err == nil {
			for _, ln := range strings.Split(string(b), "\n") {
				if ln = strings.TrimSpace(ln); ln != "" && !strings.HasPrefix(ln, "#") {
					cron = append(cron, filepath.Base(f)+": "+ln)
				}
			}
		}
	}
	out = append(out, finding(lang, cat, atr(lang, "pl_cron"), "info", cron, atr(lang, "pl_cron_ok")))

	var rc []string
	home, _ := os.UserHomeDir()
	rcFiles := []string{
		"/etc/rc.local",
		"/etc/bash.bashrc",
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".config/fish/config.fish"),
	}
	if ents, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, e := range ents {
			rcFiles = append(rcFiles, filepath.Join("/etc/profile.d", e.Name()))
		}
	}
	for _, f := range rcFiles {
		if b, err := os.ReadFile(f); err == nil {
			for _, ln := range strings.Split(string(b), "\n") {
				l := strings.ToLower(strings.TrimSpace(ln))
				if strings.HasPrefix(l, "#") {
					continue
				}
				if strings.Contains(l, "curl ") || strings.Contains(l, "wget ") ||
					strings.Contains(l, "base64") || strings.Contains(l, "/dev/tcp/") ||
					strings.Contains(l, "nc ") || strings.Contains(l, "ncat") ||
					strings.Contains(l, "ld_preload") || strings.Contains(l, "ld_library_path") {
					rc = append(rc, filepath.Base(f)+": "+strings.TrimSpace(ln))
				}
			}
		}
	}
	out = append(out, finding(lang, cat, atr(lang, "pl_rc"), "risk", rc, atr(lang, "pl_rc_ok")))

	var autostart []string
	for _, d := range []string{filepath.Join(home, ".config/autostart"), "/etc/xdg/autostart"} {
		if ents, err := os.ReadDir(d); err == nil {
			for _, e := range ents {
				autostart = append(autostart, e.Name())
			}
		}
	}
	out = append(out, finding(lang, cat, atr(lang, "pl_auto"), "info", autostart, atr(lang, "pl_auto_ok")))

	var units []string
	if ents, err := os.ReadDir(filepath.Join(home, ".config/systemd/user")); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".service") || strings.HasSuffix(e.Name(), ".timer") {
				units = append(units, e.Name())
			}
		}
	}
	out = append(out, finding(lang, cat, atr(lang, "pl_systemd"), "warn", units, atr(lang, "pl_systemd_ok")))
	return out
}

// ── Hardening ────────────────────────────────────────────────────────────────

func auditHardening(lang string) []AuditCheck {
	if runtime.GOOS == "windows" {
		return auditHardeningWindows(lang)
	}
	return auditHardeningLinux(lang)
}

func auditHardeningWindows(lang string) []AuditCheck {
	cat := atr(lang, "cat_harden")
	var out []AuditCheck

	fw := strings.ToLower(runCmd(8*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state"))
	if off := strings.Count(fw, "off"); off > 0 {
		out = append(out, AuditCheck{cat, atr(lang, "hw_fw"), "risk", fmt.Sprintf(atr(lang, "fw_off"), off)})
	} else if strings.Contains(fw, "on") {
		out = append(out, AuditCheck{cat, atr(lang, "hw_fw"), "ok", atr(lang, "fw_on")})
	} else {
		out = append(out, AuditCheck{cat, atr(lang, "hw_fw"), "info", atr(lang, "fw_unknown")})
	}

	mp := strings.TrimSpace(runCmd(15*time.Second, "powershell", "-NoProfile", "-Command",
		"$s=Get-MpComputerStatus; \"$($s.RealTimeProtectionEnabled);$($s.AntivirusSignatureAge)\""))
	if mp != "" {
		parts := strings.SplitN(mp, ";", 2)
		age := ""
		if len(parts) > 1 {
			age = strings.TrimSpace(parts[1])
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "True") {
			out = append(out, AuditCheck{cat, atr(lang, "hw_def"), "ok", fmt.Sprintf(atr(lang, "def_on"), age)})
		} else {
			out = append(out, AuditCheck{cat, atr(lang, "hw_def"), "risk", atr(lang, "def_off")})
		}
	} else {
		out = append(out, AuditCheck{cat, atr(lang, "hw_def"), "info", atr(lang, "def_na")})
	}

	rdp := runCmd(6*time.Second, "reg", "query",
		`HKLM\System\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	if strings.Contains(rdp, "0x0") {
		out = append(out, AuditCheck{cat, atr(lang, "hw_rdp"), "warn", atr(lang, "rdp_on")})
	} else if strings.Contains(rdp, "0x1") {
		out = append(out, AuditCheck{cat, atr(lang, "hw_rdp"), "ok", atr(lang, "rdp_off")})
	}

	admins := parseList(runCmd(8*time.Second, "net", "localgroup", "administrators"))
	out = append(out, AuditCheck{cat, atr(lang, "hw_admins"), statusFor(len(admins) > 3, "warn"),
		strings.Join(admins, ", ")})

	out = append(out, auditHostsFile(lang, filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)))
	return out
}

func auditHardeningLinux(lang string) []AuditCheck {
	cat := atr(lang, "cat_harden")
	var out []AuditCheck

	if hasCmd("ufw") {
		if strings.Contains(strings.ToLower(runCmd(6*time.Second, "ufw", "status")), "inactive") {
			out = append(out, AuditCheck{cat, atr(lang, "hl_ufw"), "risk", atr(lang, "ufw_off")})
		} else {
			out = append(out, AuditCheck{cat, atr(lang, "hl_ufw"), "ok", atr(lang, "ufw_on")})
		}
	} else {
		out = append(out, AuditCheck{cat, atr(lang, "hl_fw"), "info", atr(lang, "ufw_na")})
	}

	if b, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		var issues []string
		for _, ln := range strings.Split(string(b), "\n") {
			l := strings.ToLower(strings.TrimSpace(ln))
			if strings.HasPrefix(l, "permitrootlogin") && strings.Contains(l, "yes") {
				issues = append(issues, "PermitRootLogin yes")
			}
			if strings.HasPrefix(l, "passwordauthentication") && strings.Contains(l, "yes") {
				issues = append(issues, "PasswordAuthentication yes")
			}
		}
		out = append(out, finding(lang, cat, atr(lang, "hl_ssh"), "warn", issues, atr(lang, "ssh_ok")))
	}

	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		var uid0 []string
		for _, ln := range strings.Split(string(b), "\n") {
			if f := strings.Split(ln, ":"); len(f) >= 3 && f[2] == "0" && f[0] != "root" {
				uid0 = append(uid0, f[0])
			}
		}
		out = append(out, finding(lang, cat, atr(lang, "hl_uid0"), "risk", uid0, atr(lang, "uid0_ok")))
	}

	out = append(out, auditSSHAuthorizedKeys(lang, cat))
	out = append(out, auditSudoers(lang, cat))
	out = append(out, auditSUID(lang, cat))
	out = append(out, auditMAC(lang, cat))
	out = append(out, auditPathWritable(lang, cat))
	out = append(out, auditHostsFile(lang, "/etc/hosts"))
	return out
}

// auditSSHAuthorizedKeys lists entries in ~/.ssh/authorized_keys so the operator
// can spot unexpected backdoor keys.
func auditSSHAuthorizedKeys(lang, cat string) AuditCheck {
	home, _ := os.UserHomeDir()
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		return AuditCheck{cat, atr(lang, "hl_authkeys"), "ok", atr(lang, "authkeys_ok")}
	}
	var keys []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// Format: <type> <base64> <comment>  — show comment if present, else key type
		label := ln
		if f := strings.Fields(ln); len(f) >= 3 {
			label = f[0] + " … " + f[2]
		} else if len(f) >= 1 {
			label = f[0]
		}
		keys = append(keys, label)
	}
	return finding(lang, cat, atr(lang, "hl_authkeys"), "warn", keys, atr(lang, "authkeys_ok"))
}

// auditSudoers reports NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/*.
func auditSudoers(lang, cat string) AuditCheck {
	files := []string{"/etc/sudoers"}
	if ents, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range ents {
			files = append(files, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}
	var hits []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			l := strings.TrimSpace(ln)
			if strings.HasPrefix(l, "#") || l == "" {
				continue
			}
			if strings.Contains(strings.ToUpper(l), "NOPASSWD") {
				hits = append(hits, filepath.Base(f)+": "+l)
			}
		}
	}
	return finding(lang, cat, atr(lang, "hl_sudo"), "warn", hits, atr(lang, "sudo_ok"))
}

// auditSUID finds SUID/SGID binaries in paths where they should never appear.
func auditSUID(lang, cat string) AuditCheck {
	var found []string
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/var/www", "/srv"} {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		// -xdev: stay on same filesystem (don't cross into /proc, network mounts, etc.)
		out := runCmd(8*time.Second, "find", dir, "-xdev", "-perm", "/6000", "-type", "f")
		for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
			if ln != "" {
				found = append(found, ln)
			}
		}
	}
	return finding(lang, cat, atr(lang, "hl_suid"), "risk", found, atr(lang, "suid_ok"))
}

// auditMAC checks whether AppArmor or SELinux is active.
func auditMAC(lang, cat string) AuditCheck {
	// AppArmor: profiles file lists one profile per line when active
	if b, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err == nil {
		n := 0
		for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if strings.TrimSpace(ln) != "" {
				n++
			}
		}
		return AuditCheck{cat, atr(lang, "hl_mac"), "ok", fmt.Sprintf(atr(lang, "mac_aa_ok"), n)}
	}
	// SELinux: enforce = 1 → enforcing, 0 → permissive
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return AuditCheck{cat, atr(lang, "hl_mac"), "ok", atr(lang, "mac_se_ok")}
		}
		return AuditCheck{cat, atr(lang, "hl_mac"), "warn", atr(lang, "mac_se_perm")}
	}
	// Neither detected
	return AuditCheck{cat, atr(lang, "hl_mac"), "info", atr(lang, "mac_na")}
}

// auditPathWritable reports world-writable directories in $PATH; an attacker
// who can write there can shadow any command.
func auditPathWritable(lang, cat string) AuditCheck {
	var writables []string
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if info.Mode()&0o002 != 0 {
			writables = append(writables, dir)
		}
	}
	return finding(lang, cat, atr(lang, "hl_path_ww"), "risk", writables, atr(lang, "path_ww_ok"))
}

func auditHostsFile(lang, path string) AuditCheck {
	cat := atr(lang, "cat_harden")
	b, err := os.ReadFile(path)
	if err != nil {
		return AuditCheck{cat, atr(lang, "hosts"), "info", fmt.Sprintf(atr(lang, "hosts_unread"), path)}
	}
	var custom []string
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.Contains(strings.ToLower(t), "localhost") {
			continue
		}
		custom = append(custom, t)
	}
	if len(custom) == 0 {
		return AuditCheck{cat, atr(lang, "hosts"), "ok", atr(lang, "hosts_clean")}
	}
	return finding(lang, cat, atr(lang, "hosts_custom"), "warn", custom, "")
}

// ── Rootkit / cross-view heuristics ─────────────────────────────────────────

func auditRootkit(lang string) []AuditCheck {
	cat := atr(lang, "cat_rk")
	var out []AuditCheck

	hpStatus := "warn"
	if runtime.GOOS == "linux" {
		hpStatus = "risk"
	}
	out = append(out, finding(lang, cat, atr(lang, "rk_hidden"), hpStatus, hiddenProcs(lang), atr(lang, "rk_hidden_ok")))
	out = append(out, auditHiddenPorts(lang, cat))

	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/etc/ld.so.preload"); err == nil && strings.TrimSpace(string(b)) != "" {
			out = append(out, AuditCheck{cat, atr(lang, "rk_preload"), "risk",
				fmt.Sprintf(atr(lang, "preload_bad"), strings.TrimSpace(string(b)))})
		} else {
			out = append(out, AuditCheck{cat, atr(lang, "rk_preload"), "ok", atr(lang, "preload_ok")})
		}
		if b, err := os.ReadFile("/proc/sys/kernel/tainted"); err == nil {
			t := strings.TrimSpace(string(b))
			if t != "" && t != "0" {
				out = append(out, AuditCheck{cat, atr(lang, "rk_tainted"), "warn", fmt.Sprintf(atr(lang, "tainted_bad"), t)})
			} else {
				out = append(out, AuditCheck{cat, atr(lang, "rk_tainted"), "ok", atr(lang, "tainted_ok")})
			}
		}
		out = append(out, finding(lang, cat, atr(lang, "rk_promisc"), "warn", promiscIfaces(), atr(lang, "promisc_ok")))
		out = append(out, auditEnvPreload(lang, cat))
		out = append(out, auditKernelModules(lang, cat))
	}
	if runtime.GOOS == "windows" {
		out = append(out, auditWinDrivers(lang, cat))
	}
	return out
}

// auditEnvPreload detects LD_PRELOAD set in /etc/environment, which is a common
// technique to inject a malicious shared library into every process on login.
func auditEnvPreload(lang, cat string) AuditCheck {
	b, err := os.ReadFile("/etc/environment")
	if err != nil {
		return AuditCheck{cat, atr(lang, "rk_env_preload"), "ok", atr(lang, "preload_ok")}
	}
	var hits []string
	for _, ln := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(ln)
		if !strings.HasPrefix(l, "#") && strings.HasPrefix(strings.ToUpper(l), "LD_PRELOAD") {
			hits = append(hits, l)
		}
	}
	if len(hits) > 0 {
		return AuditCheck{cat, atr(lang, "rk_env_preload"), "risk",
			fmt.Sprintf(atr(lang, "env_preload_bad"), strings.Join(hits, " | "))}
	}
	return AuditCheck{cat, atr(lang, "rk_env_preload"), "ok", atr(lang, "preload_ok")}
}

// auditKernelModules lists out-of-tree or unsigned kernel modules via
// /sys/module/<name>/taint. 'O' = out-of-tree, 'E' = unsigned out-of-tree.
// Proprietary drivers (nvidia, vmware) legitimately show 'O'.
func auditKernelModules(lang, cat string) AuditCheck {
	ents, err := os.ReadDir("/sys/module")
	if err != nil {
		return AuditCheck{cat, atr(lang, "rk_modules"), "info", atr(lang, "modules_na")}
	}
	var suspicious []string
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("/sys/module", e.Name(), "taint"))
		if err != nil {
			continue
		}
		t := strings.TrimSpace(string(b))
		if strings.ContainsAny(t, "OE") {
			suspicious = append(suspicious, e.Name()+" ("+t+")")
		}
	}
	return finding(lang, cat, atr(lang, "rk_modules"), "warn", suspicious, atr(lang, "modules_ok"))
}

func auditHiddenPorts(lang, cat string) AuditCheck {
	gset := map[uint32]bool{}
	if conns, err := gnet.Connections("inet"); err == nil {
		for _, c := range conns {
			if c.Status == "LISTEN" {
				gset[c.Laddr.Port] = true
			}
		}
	}
	var raw string
	switch {
	case runtime.GOOS == "windows":
		raw = runCmd(10*time.Second, "netstat", "-ano")
	case hasCmd("ss"):
		raw = runCmd(10*time.Second, "ss", "-H", "-tuln")
	default:
		raw = runCmd(10*time.Second, "netstat", "-tuln")
	}
	if strings.TrimSpace(raw) == "" {
		return AuditCheck{cat, atr(lang, "rk_ports"), "info", atr(lang, "rk_ports_na")}
	}
	var diff []string
	for _, ln := range strings.Split(raw, "\n") {
		if runtime.GOOS == "windows" && !strings.Contains(strings.ToUpper(ln), "LISTENING") {
			continue
		}
		for _, tok := range strings.Fields(ln) {
			if i := strings.LastIndex(tok, ":"); i >= 0 && i < len(tok)-1 {
				if p, err := strconv.Atoi(tok[i+1:]); err == nil && p > 0 && p <= 65535 {
					if !gset[uint32(p)] {
						diff = append(diff, fmt.Sprintf(atr(lang, "rk_port_item"), p))
					}
					break
				}
			}
		}
	}
	return finding(lang, cat, atr(lang, "rk_ports"), "warn", uniq(diff), atr(lang, "rk_ports_ok"))
}

func auditWinDrivers(lang, cat string) AuditCheck {
	var unsigned []string
	for _, ln := range strings.Split(runCmd(25*time.Second, "driverquery", "/si", "/fo", "csv"), "\n") {
		if f := strings.Split(ln, `","`); len(f) >= 3 && strings.EqualFold(strings.Trim(f[2], `"`), "FALSE") {
			unsigned = append(unsigned, strings.Trim(f[0], `"`))
		}
	}
	return finding(lang, cat, atr(lang, "rk_drivers"), "warn", unsigned, atr(lang, "drivers_ok"))
}

func parseList(out string) []string {
	var res []string
	started := false
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "----") {
			started = true
			continue
		}
		if !started || ln == "" || strings.HasPrefix(ln, "The command completed") {
			continue
		}
		res = append(res, ln)
	}
	return res
}

func statusFor(bad bool, badStatus string) string {
	if bad {
		return badStatus
	}
	return "ok"
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
