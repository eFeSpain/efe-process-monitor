package main

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ── Interface auto-detection ─────────────────────────────────────────────────

type Iface struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	Friendly string `json:"friendly"`
}

type CaptureInfo struct {
	Tshark      bool    `json:"tshark"`
	Interfaces  []Iface `json:"interfaces"`
	LocalIP     string  `json:"local_ip"`
	Adapter     string  `json:"adapter"`
	Recommended int     `json:"recommended"`
}

var (
	capMu   sync.Mutex
	capInfo *CaptureInfo
)

var ifaceLineRe = regexp.MustCompile(`^(\d+)\.\s+(.+)$`)
var ifaceFriendlyRe = regexp.MustCompile(`\((.+)\)\s*$`)

func tsharkInterfaces() []Iface {
	out, err := command("tshark", "-D").Output()
	if err != nil {
		return nil
	}
	var ifs []Iface
	for _, line := range strings.Split(string(out), "\n") {
		m := ifaceLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		name := strings.TrimSpace(m[2])
		friendly := name
		if fm := ifaceFriendlyRe.FindStringSubmatch(name); fm != nil {
			friendly = fm[1]
		}
		ifs = append(ifs, Iface{idx, name, friendly})
	}
	return ifs
}

func adapterForIP(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
				return ifc.Name
			}
		}
	}
	return ""
}

func detectCapture() *CaptureInfo {
	ifs := tsharkInterfaces()
	info := &CaptureInfo{Tshark: len(ifs) > 0, Interfaces: ifs}
	if len(ifs) == 0 {
		return info
	}
	info.LocalIP = outboundIP()
	info.Adapter = adapterForIP(info.LocalIP)
	info.Recommended = ifs[0].Index
	if info.Adapter != "" {
		al := strings.ToLower(info.Adapter)
		for _, f := range ifs { // exact friendly match (avoid Ethernet⊂vEthernet)
			if strings.ToLower(f.Friendly) == al {
				info.Recommended = f.Index
				goto done
			}
		}
		for _, f := range ifs { // parenthesized token
			if strings.Contains(strings.ToLower(f.Name), "("+al+")") {
				info.Recommended = f.Index
				break
			}
		}
	}
done:
	return info
}

func captureInfo(refresh bool) *CaptureInfo {
	capMu.Lock()
	defer capMu.Unlock()
	if refresh || capInfo == nil {
		capInfo = detectCapture()
	}
	return capInfo
}

// ── Live packet capture ──────────────────────────────────────────────────────

// captureFields are the tshark -e fields, in the order parsePacket expects.
var captureFields = []string{
	"frame.time_epoch", "frame.len", "eth.src", "eth.dst", "ip.src", "ip.dst",
	"ip.proto", "ip.ttl", "tcp.srcport", "tcp.dstport", "tcp.flags",
	"tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.seq", "tcp.ack",
	"tcp.window_size", "udp.srcport", "udp.dstport", "dns.qry.name",
	"http.host", "http.request.uri", "http.response.code", "http.user_agent",
	"tls.handshake.extensions_server_name",
	// added: real protocol label (incl. QUIC), info column and HTTP method
	"_ws.col.protocol", "_ws.col.info", "http.request.method",
}

var packetKeys = []string{
	"time", "len", "eth_src", "eth_dst", "ip_src", "ip_dst", "ip_proto", "ttl",
	"tcp_src", "tcp_dst", "tcp_flags", "syn", "ack", "fin", "seq", "ack_num",
	"win", "udp_src", "udp_dst", "dns", "http_host", "http_uri", "http_code",
	"ua", "tls_sni",
	"proto", "info", "http_method",
}

func bpf(localIP, remoteIP string) string {
	return "host " + localIP + " and host " + remoteIP
}

func buildCaptureCmd(localIP, remoteIP, iface string, count int) *exec.Cmd {
	args := []string{"-i", iface, "-f", bpf(localIP, remoteIP), "-T", "fields"}
	for _, f := range captureFields {
		args = append(args, "-e", f)
	}
	args = append(args, "-l")
	if count > 0 {
		args = append(args, "-c", strconv.Itoa(count))
	}
	return command("tshark", args...)
}

// buildPcapCmd writes a real pcap to stdout (for download/Wireshark), bounded by
// packet count and a duration so it can't hang on idle connections.
func buildPcapCmd(localIP, remoteIP, iface string, count, seconds int) *exec.Cmd {
	return command("tshark", "-i", iface, "-f", bpf(localIP, remoteIP),
		"-w", "-", "-c", strconv.Itoa(count), "-a", "duration:"+strconv.Itoa(seconds))
}

func parsePacket(line string) map[string]string {
	parts := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
	if len(parts) < 2 {
		return nil
	}
	pkt := map[string]string{}
	for i, key := range packetKeys {
		if i < len(parts) && parts[i] != "" {
			pkt[key] = parts[i]
		}
	}
	return pkt
}

// streamCapture runs tshark and calls emit for each parsed packet until count
// packets are seen or the stop channel closes. Returns a cleaned tshark error
// (e.g. permission/Npcap issues), or "" if none.
func streamCapture(localIP, remoteIP, iface string, count int, emit func(map[string]string), stop <-chan struct{}) string {
	cmd := buildCaptureCmd(localIP, remoteIP, iface, count)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err.Error()
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return err.Error()
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if pkt := parsePacket(sc.Text()); pkt != nil {
				emit(pkt)
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-stop:
	}
	return tsharkError(errBuf.String())
}

// tsharkError strips tshark's normal chatter ("Capturing on ...") and returns
// only a real error line, if any.
func tsharkError(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "Capturing on") ||
			strings.HasPrefix(ln, "Capturing") {
			continue
		}
		l := strings.ToLower(ln)
		if strings.Contains(l, "permission") || strings.Contains(l, "npcap") ||
			strings.Contains(l, "couldn't") || strings.Contains(l, "could not") ||
			strings.Contains(l, "no such") || strings.Contains(l, "no interface") ||
			strings.Contains(l, "failed") || strings.Contains(l, "error") {
			return ln
		}
	}
	return ""
}
