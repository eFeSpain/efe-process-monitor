//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// shortConnSource owns everything in the kernel: the program, its attachment
// to the tracepoint, the ring buffer it writes to and the reader on it.
type shortConnSource struct {
	rd     *ringbuf.Reader
	tp     link.Link
	prog   *ebpf.Program
	events *ebpf.Map
	drops  *ebpf.Map
	vol    bool
}

// errNoRingBuf: the kernel predates BPF ring buffers (Linux 5.8).
var errNoRingBuf = errors.New("kernel without BPF ring buffer")

// ringBufSize is how much the kernel may queue before records are dropped
// (and counted): about 2,500 records.
const ringBufSize = 1 << 18

// openShortConnSource loads the program, attaches it and opens the reader.
// Nothing is left behind on failure.
func openShortConnSource() (*shortConnSource, error) { return openShortConnSourceSized(ringBufSize) }

// openShortConnSourceSized is openShortConnSource with a ring buffer of the
// given size (a power of two, at least a page): the tests use a small one to
// see what happens when it fills.
func openShortConnSourceSized(ringBytes uint32) (src *shortConnSource, err error) {
	_ = rlimit.RemoveMemlock() // kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK
	// Only "not supported" means an old kernel; any other answer from the
	// probe (no privileges, a locked-down kernel) is reported as it is.
	if err := features.HaveMapType(ebpf.RingBuf); errors.Is(err, ebpf.ErrNotSupported) {
		return nil, errNoRingBuf
	} else if err != nil {
		return nil, fmt.Errorf("probing for ring buffer support: %w", err)
	}
	// The program reads the tracepoint's record at fixed offsets: make sure
	// this kernel lays it out that way before attaching anything to it.
	format, err := readTracepointFormat()
	if err != nil {
		return nil, err
	}
	if err := tracepointLayout(format); err != nil {
		return nil, err
	}
	s := &shortConnSource{}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	if s.events, err = ebpf.NewMap(&ebpf.MapSpec{Name: "efemon_events", Type: ebpf.RingBuf, MaxEntries: ringBytes}); err != nil {
		return nil, fmt.Errorf("ring buffer: %w", err)
	}
	if s.drops, err = ebpf.NewMap(&ebpf.MapSpec{Name: "efemon_drops", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}); err != nil {
		return nil, fmt.Errorf("drop counter: %w", err)
	}
	// With the byte counters if this kernel says where they are — and if it
	// lets a program read them: a kernel locked down for confidentiality
	// refuses any read of kernel memory, and then the program goes without.
	vol, verr := tcpSockOffsets()
	if verr != nil {
		log.Printf("[short] brief connections will carry no byte counts: %v", verr)
	}
	s.prog, err = loadShortConnProgram(s.events.FD(), s.drops.FD(), vol)
	if err != nil && vol != nil {
		log.Printf("[short] the kernel refused the program with byte counters (%v); loading it without", err)
		vol = nil
		s.prog, err = loadShortConnProgram(s.events.FD(), s.drops.FD(), nil)
	}
	if err != nil {
		return nil, err
	}
	s.vol = vol != nil
	if s.tp, err = link.Tracepoint("sock", "inet_sock_set_state", s.prog, nil); err != nil {
		return nil, fmt.Errorf("attach to sock:inet_sock_set_state: %w", err)
	}
	if s.rd, err = ringbuf.NewReader(s.events); err != nil {
		return nil, fmt.Errorf("ring buffer reader: %w", err)
	}
	return s, nil
}

// readTracepointFormat reads the kernel's description of the tracepoint's
// record, wherever tracefs is mounted.
func readTracepointFormat() (string, error) {
	var err error
	for _, dir := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		var b []byte
		// #nosec G304 -- one of the two fixed tracefs mount points above, nothing from outside
		if b, err = os.ReadFile(dir + "/events/sock/inet_sock_set_state/format"); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("tracepoint sock:inet_sock_set_state not available: %w", err)
}

// loadShortConnProgram hands the program to the kernel's verifier. When it
// is refused, the first lines of the verifier's reasoning go into the error:
// they are what says why.
func loadShortConnProgram(eventsFD, dropsFD int, vol *volumeOffsets) (*ebpf.Program, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "efemon_tcp",
		Type:         ebpf.TracePoint,
		Instructions: shortConnProgram(eventsFD, dropsFD, vol),
		// The program is this project's (MIT); the kernel only lets
		// GPL-compatible programs call some helpers, and reads this string.
		License: "Dual MIT/GPL",
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) && len(ve.Log) > 0 {
			n := min(len(ve.Log), 6)
			return nil, fmt.Errorf("verifier: %w — %v", err, ve.Log[len(ve.Log)-n:])
		}
		return nil, err
	}
	return prog, nil
}

// next blocks until the kernel has a record (or the deadline passes) and
// returns it decoded. A record that does not decode is skipped.
func (s *shortConnSource) next() (kernelRecord, error) {
	for {
		raw, err := s.rd.Read()
		if err != nil {
			return kernelRecord{}, err
		}
		if r, ok := decodeKernelRecord(raw.RawSample); ok {
			return r, nil
		}
	}
}

func (s *shortConnSource) setDeadline(t time.Time) { s.rd.SetDeadline(t) }

// lost is how many records the kernel could not queue since the program was
// loaded: the ring buffer was full.
func (s *shortConnSource) lost() uint64 {
	var n uint64
	if err := s.drops.Lookup(uint32(0), &n); err != nil {
		return 0
	}
	return n
}

// volume reports whether the loaded program reads byte counters.
func (s *shortConnSource) volume() bool { return s.vol }

// Close detaches the program and releases everything. Safe on a source that
// was only partly opened.
func (s *shortConnSource) Close() error {
	if s.rd != nil {
		s.rd.Close()
	}
	if s.tp != nil {
		s.tp.Close()
	}
	if s.prog != nil {
		s.prog.Close()
	}
	if s.events != nil {
		s.events.Close()
	}
	if s.drops != nil {
		s.drops.Close()
	}
	return nil
}

// startShortConns turns the feature on if it can: it returns the channel the
// kernel's records arrive on and whether they carry byte counts. A nil
// channel means it is not running, and shortConnStatus says why. Never fatal:
// without it the monitor has the poll alone, as it always did.
func startShortConns() (records <-chan kernelRecord, volume bool) {
	switch {
	case !shortConnsEnabled.Load():
		setShortConnStatus("off", "")
		return nil, false
	case os.Geteuid() != 0:
		setShortConnStatus("root", "")
		return nil, false
	}
	src, err := openShortConnSource()
	switch {
	case errors.Is(err, errNoRingBuf):
		setShortConnStatus("ringbuf", "")
		return nil, false
	case err != nil:
		setShortConnStatus("refused", err.Error())
		return nil, false
	}
	setShortConnStatus("active", "")
	ch := make(chan kernelRecord, 1024)
	go forwardShortConns(src, ch)
	return ch, src.volume()
}

// shortConnKeepLoopback makes the reader pass loopback records on. The
// kernel tests set it: loopback is all a test VM has.
var shortConnKeepLoopback bool

// forwardShortConns moves records from the kernel to the monitor. The send
// blocks on purpose: if the monitor is busy the records wait in the kernel's
// buffer, where an overflow is counted, instead of piling up here.
//
// The channel is never closed: a reader that fails stops sending, says so in
// the status and the log, and the monitor carries on with the poll.
func forwardShortConns(src *shortConnSource, ch chan<- kernelRecord) {
	defer src.Close()
	var reported uint64
	nextCheck := time.Now().Add(time.Minute)
	for {
		src.setDeadline(nextCheck)
		r, err := src.next()
		switch {
		case err == nil && loopbackRecord(r) && !shortConnKeepLoopback:
			// Not followed by the monitor; dropped here, not there.
		case err == nil:
			// Who the process is, while it is still there to ask: the
			// monitor may be in the middle of a poll pass.
			if r.Kind == recStart && r.PID > 0 && r.PID <= math.MaxInt32 && int32(r.PID) != ownPID {
				r.Name, r.Exe = procNameExe(int32(r.PID))
			}
			ch <- r
		case errors.Is(err, os.ErrDeadlineExceeded):
		default:
			log.Printf("[short] the kernel reader stopped: %v", err)
			setShortConnStatus("stopped", err.Error())
			return
		}
		if now := time.Now(); !now.Before(nextCheck) {
			nextCheck = now.Add(time.Minute)
			if lost := src.lost(); lost > reported {
				log.Printf("[short] %d records lost in the last minute: the kernel buffer was full", lost-reported)
				reported = lost
			}
		}
	}
}
