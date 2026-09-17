package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// AuditCheck is one finding of the machine audit.
type AuditCheck struct {
	Category string   `json:"category"`
	Key      string   `json:"key"` // stable id of the check (its i18n key); the diff is keyed on it
	Name     string   `json:"name"`
	Status   string   `json:"status"` // ok | warn | risk | info
	Detail   string   `json:"detail"`
	Items    []string `json:"items,omitempty"` // raw findings, language-neutral where possible
	New      []string `json:"new,omitempty"`   // items first seen recently (see applyAuditDiff)
}

// auditStrings holds every user-facing audit string per language.
var auditStrings = map[string]map[string]string{
	"es": {
		"found_prefix": "%d encontrado(s): ", "more": " … (+%d más)",
		"check_failed":  "No se pudo comprobar (%v) — resultado indeterminado, no asumas que está limpio.",
		"check_skipped": "No disponible en este sistema operativo — esta comprobación NO se ha ejecutado. No lo interpretes como que está limpio.",
		"check_partial": " ⚠ comprobación incompleta (el comando falló o agotó el tiempo): puede haber más.",
		"cat_proc":      "Procesos", "cat_persist": "Persistencia", "cat_harden": "Hardening",
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
		"rk_preload": "/etc/ld.so.preload", "preload_bad": "Presente y no vacío (técnica de rootkit de usuario): %s",
		"preload_ok":  "Ausente o vacío.",
		"rk_tainted":  "Kernel tainted",
		"tainted_bad": "tainted=%s (módulo fuera de árbol/sin firma; puede ser legítimo: drivers propietarios)",
		"tainted_ok":  "tainted=0",
		"rk_promisc":  "Interfaces en modo promiscuo", "promisc_ok": "Ninguna interfaz en modo promiscuo.",
		"rk_drivers": "Drivers sin firma", "drivers_ok": "Todos los drivers están firmados.",
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
		"p_revshell":      "Shells con stdin/stdout en un socket (reverse shell)",
		"p_revshell_ok":   "Ninguna shell ni intérprete tiene sus flujos estándar en un socket.",
		"p_traced":        "Procesos bajo ptrace (depurador / inyección)",
		"p_traced_ok":     "Ningún proceso está siendo trazado.",
		"pl_sysd_sys":     "Unidades systemd del sistema definidas localmente",
		"pl_sysd_sys_ok":  "Sin unidades locales en /etc/systemd/system.",
		"pl_sysd_susp":    "Unidades systemd que arrancan desde rutas sospechosas",
		"pl_sysd_susp_ok": "Ninguna unidad del sistema arranca desde temp, shm ni un home.",
		"pw_winlogon":     "Winlogon Shell / Userinit",
		"winlogon_ok":     "Valores por defecto (explorer.exe / userinit.exe).",
		"pw_ifeo":         "Depuradores IFEO (Image File Execution Options)",
		"ifeo_ok":         "Sin valores Debugger en IFEO.",
		"pw_appinit":      "AppInit_DLLs",
		"appinit_ok":      "Vacío.",
		"pw_services":     "Servicios cuyo binario está en rutas escribibles por el usuario",
		"services_ok":     "Ningún servicio arranca desde Temp, AppData, Public o Downloads.",
		"pw_unquoted":     "Servicios con ruta sin comillas y con espacios",
		"unquoted_ok":     "Todas las rutas de servicio con espacios van entrecomilladas.",
		"hl_shadow":       "Permisos de passwd / shadow / sudoers",
		"shadow_ok":       "Correctos: shadow no legible por otros, passwd y sudoers no escribibles.",
		"fw_rules":        "%s: %d reglas activas.",
		"fw_none":         "Sin ufw y sin reglas en nft/iptables: el firewall no filtra nada.",
	},
	"en": {
		"found_prefix": "%d found: ", "more": " … (+%d more)",
		"check_failed":  "Could not check (%v) — result is indeterminate, do not read it as clean.",
		"check_skipped": "Not available on this operating system — this check did NOT run. Do not read it as clean.",
		"check_partial": " ⚠ incomplete check (the command failed or timed out): there may be more.",
		"cat_proc":      "Processes", "cat_persist": "Persistence", "cat_harden": "Hardening",
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
		"rk_preload": "/etc/ld.so.preload", "preload_bad": "Present and non-empty (user-mode rootkit technique): %s",
		"preload_ok":  "Absent or empty.",
		"rk_tainted":  "Kernel tainted",
		"tainted_bad": "tainted=%s (out-of-tree/unsigned module; may be legitimate: proprietary drivers)",
		"tainted_ok":  "tainted=0",
		"rk_promisc":  "Interfaces in promiscuous mode", "promisc_ok": "No interface in promiscuous mode.",
		"rk_drivers": "Unsigned drivers", "drivers_ok": "All drivers are signed.",
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
		"p_revshell":      "Shells with stdin/stdout on a socket (reverse shell)",
		"p_revshell_ok":   "No shell or interpreter has its standard streams on a socket.",
		"p_traced":        "Processes under ptrace (debugger / injection)",
		"p_traced_ok":     "No process is being traced.",
		"pl_sysd_sys":     "System-level systemd units defined locally",
		"pl_sysd_sys_ok":  "No local units in /etc/systemd/system.",
		"pl_sysd_susp":    "systemd units starting from suspicious paths",
		"pl_sysd_susp_ok": "No system unit starts from temp, shm or a home directory.",
		"pw_winlogon":     "Winlogon Shell / Userinit",
		"winlogon_ok":     "Default values (explorer.exe / userinit.exe).",
		"pw_ifeo":         "IFEO debuggers (Image File Execution Options)",
		"ifeo_ok":         "No Debugger values under IFEO.",
		"pw_appinit":      "AppInit_DLLs",
		"appinit_ok":      "Empty.",
		"pw_services":     "Services whose binary is in a user-writable path",
		"services_ok":     "No service starts from Temp, AppData, Public or Downloads.",
		"pw_unquoted":     "Services with an unquoted path containing spaces",
		"unquoted_ok":     "Every service path with spaces is quoted.",
		"hl_shadow":       "passwd / shadow / sudoers permissions",
		"shadow_ok":       "Correct: shadow not readable by others, passwd and sudoers not writable.",
		"fw_rules":        "%s: %d active rules.",
		"fw_none":         "No ufw and no nft/iptables rules: the firewall filters nothing.",
	},
	"zh": {
		"found_prefix": "发现 %d 项：", "more": " …（另有 %d 项）",
		"check_failed":  "无法检查（%v）— 结果不确定，不要视为干净。",
		"check_skipped": "此操作系统上不可用 — 此项检查未执行。不要视为干净。",
		"check_partial": " ⚠ 检查不完整（命令失败或超时）：可能还有更多。",
		"cat_proc":      "进程", "cat_persist": "持久化", "cat_harden": "加固",
		"cat_rk":       "Rootkit（启发式）",
		"p_suspath":    "从可疑路径运行的进程（Temp/Downloads…）",
		"p_suspath_ok": "没有从可疑路径运行的进程。",
		"p_masq":       "系统进程伪装",
		"p_masq_ok":    "系统进程均位于其合法路径。",
		"p_deleted":    "磁盘上程序文件已被删除的进程",
		"p_deleted_ok": "没有进程的程序文件被从磁盘删除。",
		"pw_run_susp":  "可疑的 Run 键",
		"pw_run":       "启动键（Run/RunOnce）", "pw_run_ok": "Run 中没有自启动项。",
		"pw_startup": "启动文件夹（Startup）", "pw_startup_ok": "启动文件夹为空。",
		"pw_tasks":    "可疑的计划任务",
		"pw_tasks_ok": "没有指向可疑路径的计划任务。",
		"pl_cron":     "cron 任务", "pl_cron_ok": "没有 cron 任务。",
		"pl_rc":    "rc/.bashrc 中的可疑行",
		"pl_rc_ok": "shell 启动文件中没有下载/反向 shell。",
		"pl_auto":  "桌面自启动", "pl_auto_ok": "没有自启动项。",
		"pl_systemd": "用户 systemd 单元", "pl_systemd_ok": "没有用户 systemd 单元。",
		"hw_fw": "Windows 防火墙", "fw_off": "%d 个配置文件的防火墙已禁用。",
		"fw_on": "所有配置文件均已启用。", "fw_unknown": "无法确定。",
		"hw_def": "Defender（实时保护）", "def_off": "实时保护已禁用。",
		"def_on": "已启用。病毒库已使用 %s 天。", "def_na": "不可用（使用其他杀毒软件，或权限不足？）。",
		"hw_rdp": "远程桌面（RDP）", "rdp_on": "RDP 已启用。", "rdp_off": "RDP 已禁用。",
		"hw_admins": "Administrators 组成员",
		"hosts":     "hosts 文件", "hosts_unread": "无法读取 %s",
		"hosts_clean": "没有自定义条目。", "hosts_custom": "hosts 文件（自定义条目）",
		"hl_ufw": "防火墙（ufw）", "ufw_off": "ufw 未激活。", "ufw_on": "ufw 已激活。",
		"hl_fw": "防火墙", "ufw_na": "未安装 ufw（请手动检查 iptables/nft）。",
		"hl_ssh": "SSH 配置", "ssh_ok": "SSH 已加固（禁止 root/密码登录）。",
		"hl_uid0": "UID 为 0 的账户（root 之外）", "uid0_ok": "只有 root 的 UID 为 0。",
		"rk_hidden": "隐藏进程（交叉比对）", "rk_hidden_ok": "各进程来源之间没有差异。",
		"rk_ports":    "隐藏的监听端口（交叉比对）",
		"rk_ports_ok": "监听端口没有差异。", "rk_ports_na": "无法与 netstat/ss 比对。",
		"rk_preload": "/etc/ld.so.preload", "preload_bad": "存在且非空（用户态 rootkit 技术）：%s",
		"preload_ok":  "不存在或为空。",
		"rk_tainted":  "内核 tainted",
		"tainted_bad": "tainted=%s（树外/未签名模块；可能是合法的：专有驱动）",
		"tainted_ok":  "tainted=0",
		"rk_promisc":  "处于混杂模式的接口", "promisc_ok": "没有接口处于混杂模式。",
		"rk_drivers": "未签名驱动", "drivers_ok": "所有驱动均已签名。",
		"hl_authkeys":     "已授权的 SSH 密钥（~/.ssh/authorized_keys）",
		"authkeys_ok":     "没有已授权的 SSH 密钥。",
		"hl_sudo":         "sudoers 中的 NOPASSWD 条目",
		"sudo_ok":         "sudoers 中没有 NOPASSWD 条目。",
		"hl_suid":         "危险路径中的 SUID/SGID 程序（/tmp、/home…）",
		"suid_ok":         "危险路径中没有 SUID/SGID 程序。",
		"hl_mac":          "强制访问控制（AppArmor / SELinux）",
		"mac_aa_ok":       "AppArmor 已启用（已加载 %d 个配置）。",
		"mac_se_ok":       "SELinux 处于 enforcing 模式。",
		"mac_se_perm":     "SELinux 处于 permissive 模式（只记录，不拦截）。",
		"mac_off":         "AppArmor 与 SELinux 均未启用。",
		"mac_na":          "此系统上未检测到 AppArmor/SELinux。",
		"hl_path_ww":      "PATH 中任何用户均可写的目录",
		"path_ww_ok":      "PATH 中没有全局可写的目录。",
		"rk_env_preload":  "/etc/environment 中的 LD_PRELOAD",
		"env_preload_bad": "在 /etc/environment 中检测到 LD_PRELOAD（库注入）：%s",
		"rk_modules":      "树外 / 未签名的内核模块",
		"modules_ok":      "未检测到树外模块。",
		"modules_na":      "无法读取 /sys/module。",
		"p_revshell":      "标准输入/输出连接到套接字的 shell（反向 shell）",
		"p_revshell_ok":   "没有 shell 或解释器的标准流连接到套接字。",
		"p_traced":        "处于 ptrace 之下的进程（调试器 / 注入）",
		"p_traced_ok":     "没有进程正在被跟踪。",
		"pl_sysd_sys":     "本地定义的系统级 systemd 单元",
		"pl_sysd_sys_ok":  "/etc/systemd/system 中没有本地单元。",
		"pl_sysd_susp":    "从可疑路径启动的 systemd 单元",
		"pl_sysd_susp_ok": "没有系统单元从 temp、shm 或家目录启动。",
		"pw_winlogon":     "Winlogon Shell / Userinit",
		"winlogon_ok":     "默认值（explorer.exe / userinit.exe）。",
		"pw_ifeo":         "IFEO 调试器（Image File Execution Options）",
		"ifeo_ok":         "IFEO 下没有 Debugger 值。",
		"pw_appinit":      "AppInit_DLLs",
		"appinit_ok":      "为空。",
		"pw_services":     "程序文件位于用户可写路径的服务",
		"services_ok":     "没有服务从 Temp、AppData、Public 或 Downloads 启动。",
		"pw_unquoted":     "路径未加引号且含空格的服务",
		"unquoted_ok":     "所有含空格的服务路径均已加引号。",
		"hl_shadow":       "passwd / shadow / sudoers 权限",
		"shadow_ok":       "正确：shadow 不可被其他用户读取，passwd 与 sudoers 不可写。",
		"fw_rules":        "%s：%d 条活动规则。",
		"fw_none":         "没有 ufw，也没有 nft/iptables 规则：防火墙未过滤任何流量。",
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
	auditMu    sync.Mutex // guards the maps below; never held across a scan
	auditRunMu sync.Mutex // serializes scans, so N callers cost one scan
	auditCache = map[string][]AuditCheck{}
	auditAt    = map[string]time.Time{}
)

const auditTTL = 60 * time.Second

// auditCached returns the audit for lang, running one if the cached copy is
// missing, stale, or explicitly refreshed.
//
// A full scan is expensive — driverquery, schtasks, find over /home, and on Linux
// a kill(pid,0) sweep — and it used to run with auditMu held for its entire
// duration, so /audit.json and /audit.txt blocked behind it and every click on
// "re-scan" queued another complete scan. Now the lock only covers the map
// access, and concurrent callers coalesce onto a single in-flight scan.
func auditCached(lang string, refresh bool) []AuditCheck {
	read := func() ([]AuditCheck, time.Time) {
		auditMu.Lock()
		defer auditMu.Unlock()
		return auditCache[lang], auditAt[lang]
	}
	if !refresh {
		if cached, at := read(); cached != nil && time.Since(at) < auditTTL {
			return cached
		}
	}

	start := time.Now()
	auditRunMu.Lock()
	defer auditRunMu.Unlock()

	cached, at := read()
	// Someone finished a scan while we were queued: that result is newer than
	// this request, so it satisfies even an explicit refresh.
	if cached != nil && at.After(start) {
		return cached
	}
	if !refresh && cached != nil && time.Since(at) < auditTTL {
		return cached
	}

	res := Audit(lang)
	applyAuditDiff(res)
	auditMu.Lock()
	auditCache[lang], auditAt[lang] = res, time.Now()
	auditMu.Unlock()
	return res
}

// auditTime is when the cached result for lang was produced (zero if none).
func auditTime(lang string) time.Time {
	auditMu.Lock()
	defer auditMu.Unlock()
	return auditAt[lang]
}

// Audit runs all checks for the current OS in the given language. The four
// categories are independent and each is bounded by its own command timeouts,
// so they run concurrently: the scan takes as long as the slowest one, not the
// sum — `find` over a large /home alone can use its full 20 s.
func Audit(lang string) []AuditCheck {
	cats := []func(string) []AuditCheck{auditProcesses, auditPersistence, auditHardening, auditRootkit}
	parts := make([][]AuditCheck, len(cats))
	var wg sync.WaitGroup
	for i, f := range cats {
		wg.Add(1)
		go func(i int, f func(string) []AuditCheck) {
			defer wg.Done()
			parts[i] = f(lang)
		}(i, f)
	}
	wg.Wait()
	var c []AuditCheck
	for _, p := range parts {
		c = append(c, sortBySeverity(p)...)
	}
	return c
}

// sortBySeverity orders a category's checks risk → warn → info → ok, keeping
// the original order within a level.
func sortBySeverity(in []AuditCheck) []AuditCheck {
	rank := map[string]int{"risk": 0, "warn": 1, "info": 2, "ok": 3}
	out := append([]AuditCheck(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Status] < rank[out[j].Status] })
	return out
}

// auditNewWindow is how long an item stays marked as new after it was first
// seen by a scan. "New since the last scan" would vanish on the very next
// re-scan, which is when the operator is looking; a day keeps it visible.
const auditNewWindow = 24 * time.Hour

// applyAuditDiff marks the items of each check that were not seen by earlier
// scans, and records everything seen now. The very first scan on a machine
// marks nothing: with no history, "everything is new" is noise.
func applyAuditDiff(checks []AuditCheck) {
	if db == nil {
		return
	}
	seen, hadHistory := dbAuditSeen()
	now := time.Now()
	// Items of the first scan ever are the baseline: recorded as seen "at the
	// beginning of time", so they never come up as new on the scans after it.
	mark := now
	if !hadHistory {
		mark = time.Unix(0, 0)
	}
	for i := range checks {
		c := &checks[i]
		for _, it := range c.Items {
			first, ok := seen[c.Key][it]
			if !ok {
				dbAuditMarkSeen(c.Key, it, mark)
				first = mark
			}
			if now.Sub(first) < auditNewWindow {
				c.New = append(c.New, it)
			}
		}
	}
}

// runCmd returns the command's stdout and discards any error. Only use it where
// empty output is itself a valid answer; if a failure would be mistaken for a
// clean result, use runCmdErr.
func runCmd(timeout time.Duration, name string, args ...string) string {
	out, _ := runCmdErr(timeout, name, args...)
	return out
}

// runCmdErr is runCmd but surfaces the failure, including a timeout.
//
// This matters: `find /home -perm /6000` against a big home directory routinely
// hits its deadline, and swallowing that turned "we never finished looking" into
// "no SUID binaries found". In a security audit a false OK is the worst possible
// output, so callers whose check can't distinguish the two must use this.
func runCmdErr(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := commandContext(ctx, name, args...).Output()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return string(out), err
}

// check builds one result with a fixed detail. key is the check's i18n key
// and doubles as its stable identity across scans and languages.
func check(lang, cat, key, status, detail string) AuditCheck {
	return AuditCheck{Category: cat, Key: key, Name: atr(lang, key), Status: status, Detail: detail}
}

// finding builds one check from a list of offending items. okKey is the text
// for the empty case ("" for none). The items are kept on the check as data:
// that is what the previous-scan diff compares, so they should be raw (paths,
// pids, entries) rather than prose that changes with the language.
func finding(lang, cat, key, status string, items []string, okKey string) AuditCheck {
	c := AuditCheck{Category: cat, Key: key, Name: atr(lang, key), Items: items}
	if len(items) == 0 {
		c.Status = "ok"
		if okKey != "" {
			c.Detail = atr(lang, okKey)
		}
		return c
	}
	shown, extra := items, ""
	if len(shown) > 12 {
		shown = shown[:12]
		extra = fmt.Sprintf(atr(lang, "more"), len(items)-12)
	}
	c.Status = status
	c.Detail = fmt.Sprintf(atr(lang, "found_prefix"), len(items)) + strings.Join(shown, " | ") + extra
	return c
}

// findingOrSkipped is finding() for probes that may not exist on this platform.
// When the probe did not run it reports "not available here" instead of "ok" — a
// stub returning an empty list must never render as a clean pass.
func findingOrSkipped(lang, cat, key, status string, items []string, okKey string, ran bool) AuditCheck {
	if !ran {
		return check(lang, cat, key, "info", atr(lang, "check_skipped"))
	}
	return finding(lang, cat, key, status, items, okKey)
}

// findingOrUnknown is finding() for checks backed by an external command: when
// that command failed it reports "couldn't check" instead of "ok", and when it
// produced partial output it keeps the findings but says so.
func findingOrUnknown(lang, cat, key, status string, items []string, okKey string, err error) AuditCheck {
	if err != nil && len(items) == 0 {
		return check(lang, cat, key, "info", fmt.Sprintf(atr(lang, "check_failed"), err))
	}
	c := finding(lang, cat, key, status, items, okKey)
	if err != nil {
		c.Detail += atr(lang, "check_partial")
	}
	return c
}

// ── Processes ────────────────────────────────────────────────────────────────

func auditProcesses(lang string) []AuditCheck {
	cat := atr(lang, "cat_proc")
	var susPath, masq, deleted, revshell, traced []string
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
		// /proc is Linux-only: on macOS this silently found nothing and the check
		// then reported a clean pass for something it never looked at.
		if runtime.GOOS == "linux" {
			if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.Pid)); err == nil &&
				strings.Contains(link, "(deleted)") {
				deleted = append(deleted, fmt.Sprintf("%s (pid %d) %s", name, p.Pid, link))
			}
			// A shell or interpreter whose stdin or stdout *is* a socket is the
			// reverse-shell shape: `bash -i >& /dev/tcp/…`, `python -c 'pty.spawn'`
			// after a connect, and every one-liner in every cheat sheet. Nothing
			// legitimate wires a shell's standard streams straight to a socket —
			// an ssh session gets a pty, a CGI script gets pipes.
			if shellLike[procBase(name)] {
				for _, fd := range []string{"0", "1"} {
					if t, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", p.Pid, fd)); err == nil &&
						strings.HasPrefix(t, "socket:") {
						revshell = append(revshell, fmt.Sprintf("%s (pid %d) fd%s → %s", name, p.Pid, fd, t))
						break
					}
				}
			}
			// TracerPid != 0: something has ptrace-attached. A debugger during
			// development is the benign case, hence warn; on a server it is
			// injection or credential scraping.
			if tp := tracerPid(p.Pid); tp > 0 {
				tname := "?"
				if tr, err := process.NewProcess(int32(tp)); err == nil { // #nosec G115 -- pid from /proc, < pid_max
					if n, err := tr.Name(); err == nil {
						tname = n
					}
				}
				traced = append(traced, fmt.Sprintf("%s (pid %d) ← %s (pid %d)", name, p.Pid, tname, tp))
			}
		}
	}
	out := []AuditCheck{
		finding(lang, cat, "p_suspath", "risk", susPath, "p_suspath_ok"),
	}
	switch runtime.GOOS {
	case "windows":
		out = append(out, finding(lang, cat, "p_masq", "risk", masq, "p_masq_ok"))
	case "linux":
		out = append(out, finding(lang, cat, "p_deleted", "risk", deleted, "p_deleted_ok"))
		out = append(out, finding(lang, cat, "p_revshell", "risk", revshell, "p_revshell_ok"))
		out = append(out, finding(lang, cat, "p_traced", "warn", traced, "p_traced_ok"))
	default:
		out = append(out, findingOrSkipped(lang, cat, "p_deleted", "risk", nil, "p_deleted_ok", false))
	}
	return out
}

// shellLike are the processes whose standard streams should never be a socket.
// nc/socat are deliberately absent: a socket is their whole job.
var shellLike = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "fish": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "php": true, "lua": true,
}

// tracerPid reads TracerPid from /proc/<pid>/status; 0 when not traced or unreadable.
func tracerPid(pid int32) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "TracerPid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
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
		e, su := parseRegRunLines(runCmd(8*time.Second, "reg", "query", hive))
		runEntries = append(runEntries, e...)
		runSusp = append(runSusp, su...)
	}
	if len(runSusp) > 0 {
		out = append(out, finding(lang, cat, "pw_run_susp", "risk", runSusp, ""))
	} else {
		out = append(out, finding(lang, cat, "pw_run", "info", runEntries, "pw_run_ok"))
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
	out = append(out, finding(lang, cat, "pw_startup", "warn", startup, "pw_startup_ok"))

	schtasksOut, schtasksErr := runCmdErr(30*time.Second, "schtasks", "/query", "/v", "/fo", "csv")
	out = append(out, findingOrUnknown(lang, cat, "pw_tasks", "risk", parseSchtasksSuspicious(schtasksOut),
		"pw_tasks_ok", schtasksErr))

	// Winlogon Shell / Userinit: the two values every user logon executes.
	// Malware appends itself ("userinit.exe,evil.exe"); anything but the
	// defaults is worth a look.
	var winlogon []string
	for name, want := range map[string][]string{
		"Shell":    {"explorer.exe"},
		"Userinit": {`c:\windows\system32\userinit.exe,`, `c:\windows\system32\userinit.exe`},
	} {
		got := regValue(runCmd(6*time.Second, "reg", "query",
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "/v", name))
		if got == "" {
			continue
		}
		okv := false
		for _, w := range want {
			if strings.EqualFold(strings.TrimSpace(got), w) {
				okv = true
			}
		}
		if !okv {
			winlogon = append(winlogon, name+" = "+got)
		}
	}
	out = append(out, finding(lang, cat, "pw_winlogon", "risk", winlogon, "winlogon_ok"))

	// Image File Execution Options: a Debugger value under <exe> makes Windows
	// launch that "debugger" instead — a silent hijack of any program.
	ifeo := parseIFEO(runCmd(10*time.Second, "reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "/s", "/v", "Debugger"))
	out = append(out, finding(lang, cat, "pw_ifeo", "risk", ifeo, "ifeo_ok"))

	// AppInit_DLLs: loaded into every process that links user32. Empty on a
	// healthy machine.
	var appinit []string
	for _, k := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	} {
		if v := regValue(runCmd(6*time.Second, "reg", "query", k, "/v", "AppInit_DLLs")); v != "" {
			appinit = append(appinit, v)
		}
	}
	out = append(out, finding(lang, cat, "pw_appinit", "risk", appinit, "appinit_ok"))

	// Services: the persistence that also runs as SYSTEM. Two shapes matter —
	// a binary in a user-writable directory, and an unquoted path with spaces
	// (Windows tries "C:\Program.exe" first: whoever can write there wins).
	svcOut, svcErr := runCmdErr(30*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Service | ForEach-Object { \"$($_.Name)`t$($_.State)`t$($_.PathName)\" }")
	susp, unquoted := parseWinServices(svcOut)
	out = append(out, findingOrUnknown(lang, cat, "pw_services", "risk", susp, "services_ok", svcErr))
	out = append(out, findingOrUnknown(lang, cat, "pw_unquoted", "warn", unquoted, "unquoted_ok", svcErr))
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
	out = append(out, finding(lang, cat, "pl_cron", "info", cron, "pl_cron_ok"))

	// Per-user files are checked for every real account, not "the current
	// home": run as root through sudo, HOME is /root, and the audit used to
	// inspect root's .bashrc and autostart while the logged-in user's — the
	// ones an attacker actually plants in — went unread. Homes we cannot read
	// (unprivileged run) are skipped silently.
	var rc []string
	rcFiles := []string{"/etc/rc.local", "/etc/bash.bashrc"}
	if ents, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, e := range ents {
			rcFiles = append(rcFiles, filepath.Join("/etc/profile.d", e.Name()))
		}
	}
	for _, f := range rcFiles {
		rc = append(rc, suspiciousRCLines(f, filepath.Base(f))...)
	}
	homes := userHomes()
	for _, u := range homes {
		for _, rel := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".config/fish/config.fish"} {
			rc = append(rc, suspiciousRCLines(filepath.Join(u.home, rel), u.name+": ~/"+rel)...)
		}
	}
	out = append(out, finding(lang, cat, "pl_rc", "risk", rc, "pl_rc_ok"))

	var autostart []string
	if ents, err := os.ReadDir("/etc/xdg/autostart"); err == nil {
		for _, e := range ents {
			autostart = append(autostart, e.Name())
		}
	}
	for _, u := range homes {
		if ents, err := os.ReadDir(filepath.Join(u.home, ".config/autostart")); err == nil {
			for _, e := range ents {
				autostart = append(autostart, u.name+": "+e.Name())
			}
		}
	}
	out = append(out, finding(lang, cat, "pl_auto", "info", autostart, "pl_auto_ok"))

	var units []string
	for _, u := range homes {
		if ents, err := os.ReadDir(filepath.Join(u.home, ".config/systemd/user")); err == nil {
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".service") || strings.HasSuffix(e.Name(), ".timer") {
					units = append(units, u.name+": "+e.Name())
				}
			}
		}
	}
	out = append(out, finding(lang, cat, "pl_systemd", "warn", units, "pl_systemd_ok"))
	out = append(out, auditSystemdSystem(lang, cat)...)
	return out
}

// suspiciousRCLines returns the lines of a shell start-up file that download,
// decode, open a raw TCP connection or preload a library — labelled with where
// they were found.
func suspiciousRCLines(path, label string) []string {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed list of shell start-up files
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		l := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "curl ") || strings.Contains(l, "wget ") ||
			strings.Contains(l, "base64") || strings.Contains(l, "/dev/tcp/") ||
			strings.Contains(l, "nc ") || strings.Contains(l, "ncat") ||
			strings.Contains(l, "ld_preload") || strings.Contains(l, "ld_library_path") {
			out = append(out, label+": "+strings.TrimSpace(ln))
		}
	}
	return out
}

// auditSystemdSystem looks at the system-level units — the most common Linux
// persistence, and the one this audit did not cover. Units *defined* locally
// (regular files in /etc/systemd/system, not the enable-symlinks into
// /usr/lib) are listed as information; any whose Exec* line starts something
// from a staging or home directory is a finding.
func auditSystemdSystem(lang, cat string) []AuditCheck {
	var local, susp []string
	for _, dir := range []string{"/etc/systemd/system", "/usr/local/lib/systemd/system"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || e.Type()&os.ModeSymlink != 0 ||
				!(strings.HasSuffix(n, ".service") || strings.HasSuffix(n, ".timer")) {
				continue
			}
			local = append(local, n)
			b, err := os.ReadFile(filepath.Join(dir, n)) // #nosec G304 -- unit files under a fixed directory
			if err != nil {
				continue
			}
			for _, ex := range parseSystemdExec(string(b)) {
				if suspiciousExecPath(ex) {
					susp = append(susp, n+": "+ex)
				}
			}
		}
	}
	return []AuditCheck{
		finding(lang, cat, "pl_sysd_susp", "risk", susp, "pl_sysd_susp_ok"),
		finding(lang, cat, "pl_sysd_sys", "info", local, "pl_sysd_sys_ok"),
	}
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

	out = append(out, auditWinFirewall(lang, cat))

	mp := strings.TrimSpace(runCmd(15*time.Second, "powershell", "-NoProfile", "-Command",
		"$s=Get-MpComputerStatus; \"$($s.RealTimeProtectionEnabled);$($s.AntivirusSignatureAge)\""))
	if mp != "" {
		parts := strings.SplitN(mp, ";", 2)
		age := ""
		if len(parts) > 1 {
			age = strings.TrimSpace(parts[1])
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "True") {
			out = append(out, check(lang, cat, "hw_def", "ok", fmt.Sprintf(atr(lang, "def_on"), age)))
		} else {
			out = append(out, check(lang, cat, "hw_def", "risk", atr(lang, "def_off")))
		}
	} else {
		out = append(out, check(lang, cat, "hw_def", "info", atr(lang, "def_na")))
	}

	rdp := runCmd(6*time.Second, "reg", "query",
		`HKLM\System\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	if strings.Contains(rdp, "0x0") {
		out = append(out, check(lang, cat, "hw_rdp", "warn", atr(lang, "rdp_on")))
	} else if strings.Contains(rdp, "0x1") {
		out = append(out, check(lang, cat, "hw_rdp", "ok", atr(lang, "rdp_off")))
	}

	// Locale-independent: `net localgroup administrators` fails on a non-English
	// Windows (the group is "Administradores", "Administratoren", …) and its
	// output was parsed by looking for the English "The command completed".
	// The well-known SID S-1-5-32-544 is the same on every install.
	adminOut, adminErr := runCmdErr(20*time.Second, "powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }) -join ';'")
	var admins []string
	for _, m := range strings.Split(strings.TrimSpace(adminOut), ";") {
		if m = strings.TrimSpace(m); m != "" {
			admins = append(admins, m)
		}
	}
	switch {
	case len(admins) > 0:
		c := check(lang, cat, "hw_admins", statusFor(len(admins) > 3, "warn"), strings.Join(admins, ", "))
		c.Items = admins // members are the raw items: a new administrator is what the NEW badge is for
		out = append(out, c)
	default:
		out = append(out, check(lang, cat, "hw_admins", "info", fmt.Sprintf(atr(lang, "check_failed"), adminErr)))
	}

	out = append(out, auditHostsFile(lang, filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)))
	return out
}

// auditWinFirewall reports the per-profile firewall state.
//
// It used to count the substring "off" in `netsh advfirewall show allprofiles`
// output, which only works on an English Windows: on a Spanish install the state
// reads "ACTIVADO"/"DESACTIVADO", so the count was 0, "on" was absent too, and
// the check reported "could not determine" — every time, on the maintainer's own
// machine. Get-NetFirewallProfile returns True/False regardless of system
// language, so the parse is locale-independent.
func auditWinFirewall(lang, cat string) AuditCheck {
	out, err := runCmdErr(20*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetFirewallProfile -PolicyStore ActiveStore | "+
			"ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }) -join ';'")
	var off, on []string
	for _, part := range strings.Split(strings.TrimSpace(out), ";") {
		name, state, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		// Enabled renders as True/False (or 1/0 on some builds).
		switch strings.ToLower(strings.TrimSpace(state)) {
		case "true", "1":
			on = append(on, name)
		case "false", "0":
			off = append(off, name)
		}
	}
	switch {
	case len(off) > 0:
		return check(lang, cat, "hw_fw", "risk", fmt.Sprintf(atr(lang, "fw_off"), len(off))+" ("+strings.Join(off, ", ")+")")
	case len(on) > 0:
		return check(lang, cat, "hw_fw", "ok", atr(lang, "fw_on"))
	case err != nil:
		return check(lang, cat, "hw_fw", "info", fmt.Sprintf(atr(lang, "check_failed"), err))
	default:
		return check(lang, cat, "hw_fw", "info", atr(lang, "fw_unknown"))
	}
}

func auditHardeningLinux(lang string) []AuditCheck {
	cat := atr(lang, "cat_harden")
	var out []AuditCheck

	// Without ufw the rules may still be there, written by hand or by a
	// firewalld/nftables service; "check manually" was the answer for every
	// Debian/Arch box. Count the active rules instead.
	switch {
	case hasCmd("ufw"):
		if strings.Contains(strings.ToLower(runCmd(6*time.Second, "ufw", "status")), "inactive") {
			out = append(out, check(lang, cat, "hl_ufw", "risk", atr(lang, "ufw_off")))
		} else {
			out = append(out, check(lang, cat, "hl_ufw", "ok", atr(lang, "ufw_on")))
		}
	case hasCmd("nft"):
		if n := countNftRules(runCmd(6*time.Second, "nft", "list", "ruleset")); n > 0 {
			out = append(out, check(lang, cat, "hl_fw", "ok", fmt.Sprintf(atr(lang, "fw_rules"), "nft", n)))
		} else {
			out = append(out, check(lang, cat, "hl_fw", "warn", atr(lang, "fw_none")))
		}
	case hasCmd("iptables"):
		if n := countIptablesRules(runCmd(6*time.Second, "iptables", "-S")); n > 0 {
			out = append(out, check(lang, cat, "hl_fw", "ok", fmt.Sprintf(atr(lang, "fw_rules"), "iptables", n)))
		} else {
			out = append(out, check(lang, cat, "hl_fw", "warn", atr(lang, "fw_none")))
		}
	default:
		out = append(out, check(lang, cat, "hl_fw", "info", atr(lang, "ufw_na")))
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
		out = append(out, finding(lang, cat, "hl_ssh", "warn", issues, "ssh_ok"))
	}

	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		var uid0 []string
		for _, ln := range strings.Split(string(b), "\n") {
			if f := strings.Split(ln, ":"); len(f) >= 3 && f[2] == "0" && f[0] != "root" {
				uid0 = append(uid0, f[0])
			}
		}
		out = append(out, finding(lang, cat, "hl_uid0", "risk", uid0, "uid0_ok"))
	}

	out = append(out, auditSSHAuthorizedKeys(lang, cat))
	out = append(out, auditShadowPerms(lang, cat))
	out = append(out, auditSudoers(lang, cat))
	out = append(out, auditSUID(lang, cat))
	out = append(out, auditMAC(lang, cat))
	out = append(out, auditPathWritable(lang, cat))
	out = append(out, auditHostsFile(lang, "/etc/hosts"))
	return out
}

// auditSSHAuthorizedKeys lists the entries of every user's authorized_keys so
// the operator can spot a backdoor key. A file we could not read is reported
// as such: "no keys" and "not allowed to look" are different answers.
func auditSSHAuthorizedKeys(lang, cat string) AuditCheck {
	var keys []string
	var unreadable error
	for _, u := range userHomes() {
		p := filepath.Join(u.home, ".ssh", "authorized_keys")
		b, err := os.ReadFile(p) // #nosec G304 -- fixed path under each user's home
		if err != nil {
			if !os.IsNotExist(err) && unreadable == nil {
				unreadable = fmt.Errorf("%s: %w", p, err)
			}
			continue
		}
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
			keys = append(keys, u.name+": "+label)
		}
	}
	return findingOrUnknown(lang, cat, "hl_authkeys", "warn", keys, "authkeys_ok", unreadable)
}

// auditShadowPerms: /etc/shadow readable by others hands out every password
// hash; /etc/passwd or sudoers writable by others hands out root.
func auditShadowPerms(lang, cat string) AuditCheck {
	var bad []string
	for _, f := range []struct {
		path string
		mask os.FileMode
	}{{"/etc/shadow", 0o004}, {"/etc/gshadow", 0o004}, {"/etc/passwd", 0o002}, {"/etc/sudoers", 0o002}, {"/etc/group", 0o002}} {
		fi, err := os.Stat(f.path)
		if err != nil {
			continue
		}
		if fi.Mode().Perm()&f.mask != 0 {
			bad = append(bad, f.path+" "+fi.Mode().Perm().String())
		}
	}
	return finding(lang, cat, "hl_shadow", "risk", bad, "shadow_ok")
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
	return finding(lang, cat, "hl_sudo", "warn", hits, "sudo_ok")
}

// auditSUID finds SUID/SGID binaries in paths where they should never appear.
func auditSUID(lang, cat string) AuditCheck {
	var found []string
	var failed error
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/var/www", "/srv"} {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		// -xdev: stay on same filesystem (don't cross into /proc, network mounts, etc.)
		// A large /home regularly exceeds the deadline, so the error is kept and
		// reported rather than turned into a clean bill of health.
		out, err := runCmdErr(20*time.Second, "find", dir, "-xdev", "-perm", "/6000", "-type", "f")
		if err != nil && failed == nil {
			failed = err
		}
		for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
			if ln != "" {
				found = append(found, ln)
			}
		}
	}
	return findingOrUnknown(lang, cat, "hl_suid", "risk", found, "suid_ok", failed)
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
		return check(lang, cat, "hl_mac", "ok", fmt.Sprintf(atr(lang, "mac_aa_ok"), n))
	}
	// SELinux: enforce = 1 → enforcing, 0 → permissive
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return check(lang, cat, "hl_mac", "ok", atr(lang, "mac_se_ok"))
		}
		return check(lang, cat, "hl_mac", "warn", atr(lang, "mac_se_perm"))
	}
	// Neither detected
	return check(lang, cat, "hl_mac", "info", atr(lang, "mac_na"))
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
	return finding(lang, cat, "hl_path_ww", "risk", writables, "path_ww_ok")
}

func auditHostsFile(lang, path string) AuditCheck {
	cat := atr(lang, "cat_harden")
	b, err := os.ReadFile(path)
	if err != nil {
		return check(lang, cat, "hosts", "info", fmt.Sprintf(atr(lang, "hosts_unread"), path))
	}
	hn, _ := os.Hostname()
	custom := customHostsLines(string(b), hn)
	if len(custom) == 0 {
		return check(lang, cat, "hosts", "ok", atr(lang, "hosts_clean"))
	}
	return finding(lang, cat, "hosts_custom", "warn", custom, "")
}

// ── Rootkit / cross-view heuristics ─────────────────────────────────────────

func auditRootkit(lang string) []AuditCheck {
	cat := atr(lang, "cat_rk")
	var out []AuditCheck

	hpStatus := "warn"
	if runtime.GOOS == "linux" {
		hpStatus = "risk"
	}
	hidden, hpRan, hpPartial := hiddenProcs()
	hp := findingOrSkipped(lang, cat, "rk_hidden", hpStatus, hidden, "rk_hidden_ok", hpRan)
	if hpPartial {
		hp.Detail += atr(lang, "check_partial")
	}
	out = append(out, hp)
	out = append(out, auditHiddenPorts(lang, cat))

	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/etc/ld.so.preload"); err == nil && strings.TrimSpace(string(b)) != "" {
			out = append(out, check(lang, cat, "rk_preload", "risk", fmt.Sprintf(atr(lang, "preload_bad"), strings.TrimSpace(string(b)))))
		} else {
			out = append(out, check(lang, cat, "rk_preload", "ok", atr(lang, "preload_ok")))
		}
		if b, err := os.ReadFile("/proc/sys/kernel/tainted"); err == nil {
			t := strings.TrimSpace(string(b))
			if t != "" && t != "0" {
				out = append(out, check(lang, cat, "rk_tainted", "warn", fmt.Sprintf(atr(lang, "tainted_bad"), t)))
			} else {
				out = append(out, check(lang, cat, "rk_tainted", "ok", atr(lang, "tainted_ok")))
			}
		}
		promisc, promiscRan := promiscIfaces()
		out = append(out, findingOrSkipped(lang, cat, "rk_promisc", "warn", promisc, "promisc_ok", promiscRan))
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
		return check(lang, cat, "rk_env_preload", "ok", atr(lang, "preload_ok"))
	}
	var hits []string
	for _, ln := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(ln)
		if !strings.HasPrefix(l, "#") && strings.HasPrefix(strings.ToUpper(l), "LD_PRELOAD") {
			hits = append(hits, l)
		}
	}
	if len(hits) > 0 {
		return check(lang, cat, "rk_env_preload", "risk", fmt.Sprintf(atr(lang, "env_preload_bad"), strings.Join(hits, " | ")))
	}
	return check(lang, cat, "rk_env_preload", "ok", atr(lang, "preload_ok"))
}

// auditKernelModules lists out-of-tree or unsigned kernel modules via
// /sys/module/<name>/taint. 'O' = out-of-tree, 'E' = unsigned out-of-tree.
// Proprietary drivers (nvidia, vmware) legitimately show 'O'.
func auditKernelModules(lang, cat string) AuditCheck {
	ents, err := os.ReadDir("/sys/module")
	if err != nil {
		return check(lang, cat, "rk_modules", "info", atr(lang, "modules_na"))
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
	return finding(lang, cat, "rk_modules", "warn", suspicious, "modules_ok")
}

func auditHiddenPorts(lang, cat string) AuditCheck {
	// The API-side set must cover the same protocols as the command we compare
	// against. It used to collect only Status=="LISTEN", which excludes every UDP
	// socket (gopsutil gives datagram sockets no state), while `ss -tuln` lists
	// them — so every open UDP port was reported as a hidden rootkit port.
	gset := map[uint32]bool{}
	if conns, err := gnet.Connections("inet"); err == nil {
		for _, c := range conns {
			if c.Status == "LISTEN" || isUDP(c) {
				gset[c.Laddr.Port] = true
			}
		}
	}
	var raw string
	var err error
	switch {
	case runtime.GOOS == "windows":
		raw, err = runCmdErr(10*time.Second, "netstat", "-ano")
	case hasCmd("ss"):
		raw, err = runCmdErr(10*time.Second, "ss", "-H", "-tuln")
	default:
		raw, err = runCmdErr(10*time.Second, "netstat", "-tuln")
	}
	if err != nil || strings.TrimSpace(raw) == "" {
		return check(lang, cat, "rk_ports", "info", atr(lang, "rk_ports_na"))
	}
	var diff []string
	for _, p := range parseListeningPorts(raw, runtime.GOOS == "windows") {
		if !gset[uint32(p)] { // #nosec G115 -- parseListeningPorts bounds p to 1..65535
			diff = append(diff, strconv.Itoa(p))
		}
	}
	return finding(lang, cat, "rk_ports", "warn", uniq(diff), "rk_ports_ok")
}

func auditWinDrivers(lang, cat string) AuditCheck {
	out, err := runCmdErr(25*time.Second, "driverquery", "/si", "/fo", "csv")
	return findingOrUnknown(lang, cat, "rk_drivers", "warn", parseDriverQueryUnsigned(out), "drivers_ok", err)
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
