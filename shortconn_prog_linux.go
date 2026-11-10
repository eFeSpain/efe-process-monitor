//go:build linux

package main

import (
	"github.com/cilium/ebpf/asm"
)

// The kernel half of brief connections: an eBPF program attached to the
// tracepoint sock:inet_sock_set_state, which the kernel fires on every state
// change of a TCP socket. It is written here, in Go, with the library's
// assembler — no C source, no compiled object in the repository.
//
// The kernel verifies the program before accepting it (every memory access
// bounded, no unbounded loops): one it cannot prove safe is refused at load.
//
// What it does: for a TCP socket entering SYN_SENT, ESTABLISHED or CLOSE it
// writes one 104-byte record (layout: kernelRecordSize, shortconn.go) to a
// ring buffer. Entering SYN_SENT happens inside the connect() system call, so
// only there is "the current process" the one that owns the connection, and
// only there is it recorded.

// Offsets in the tracepoint's own record. A stable kernel interface since
// Linux 4.16, pinned by TestKernelTracepointExists.
const (
	tpSkaddr   = 8  // const void *
	tpOldState = 16 // int
	tpNewState = 20 // int
	tpSport    = 24 // u16, host byte order: the socket's local port
	tpDport    = 26 // u16, host byte order
	tpFamily   = 28 // u16
	tpProtocol = 30 // u16
	tpAddrs    = 32 // saddr[4] daddr[4] saddr_v6[16] daddr_v6[16] — 40 bytes, up to 72

	ipprotoTCP = 6
	tcpClose   = 7
)

// The record is built on the stack, below the frame pointer; the 4-byte key
// for the drop counter sits under it.
const (
	recBase int16 = -kernelRecordSize // fp-104
	keySlot int16 = recBase - 4       // fp-108
)

// volumeOffsets are the byte offsets of the counters in struct tcp_sock.
type volumeOffsets struct{ sent, recv int32 }

// shortConnProgram assembles the program. events is the ring buffer, drops
// an array map with one u64 counting records that did not fit. vol nil
// leaves the byte counters out.
//
// Registers: r6 = the tracepoint record (the program's argument), r8 = the
// kind of record being built. Both survive helper calls; r0–r5 do not.
func shortConnProgram(eventsFD, dropsFD int, vol *volumeOffsets) asm.Instructions {
	rec := func(off int16) int16 { return recBase + off }

	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),

		// Only TCP.
		asm.LoadMem(asm.R0, asm.R6, tpProtocol, asm.Half),
		asm.JNE.Imm(asm.R0, ipprotoTCP, "exit"),

		// Only three destinations: connect() started, handshake done, gone.
		asm.LoadMem(asm.R7, asm.R6, tpNewState, asm.Word),
		asm.Mov.Imm(asm.R8, recStart),
		asm.JEq.Imm(asm.R7, tcpSynSent, "build"),
		asm.Mov.Imm(asm.R8, recEstablished),
		asm.JEq.Imm(asm.R7, tcpEstablished, "build"),
		asm.Mov.Imm(asm.R8, recClosed),
		asm.JEq.Imm(asm.R7, tcpClose, "build"),
		asm.Ja.Label("exit"),
	}

	// Zero the whole record first: the verifier refuses to hand uninitialised
	// stack to the ring buffer, and fields a kind does not set must be 0.
	// (From a register: the assembler has no 8-byte immediate store.)
	ins = append(ins, asm.Mov.Imm(asm.R0, 0).WithSymbol("build"))
	for off := int16(0); off < kernelRecordSize; off += 8 {
		ins = append(ins, asm.StoreMem(asm.RFP, rec(off), asm.R0, asm.DWord))
	}

	ins = append(ins,
		// ts: the kernel's monotonic clock.
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, rec(0), asm.R0, asm.DWord),
		// sock: the socket's address, its identity while it lives.
		asm.LoadMem(asm.R0, asm.R6, tpSkaddr, asm.DWord),
		asm.StoreMem(asm.RFP, rec(8), asm.R0, asm.DWord),
		// kind, and the state the socket is leaving.
		asm.StoreMem(asm.RFP, rec(24), asm.R8, asm.Byte),
		asm.LoadMem(asm.R0, asm.R6, tpOldState, asm.Word),
		asm.StoreMem(asm.RFP, rec(25), asm.R0, asm.Byte),
		// family, local port, remote port.
		asm.LoadMem(asm.R0, asm.R6, tpFamily, asm.Half),
		asm.StoreMem(asm.RFP, rec(26), asm.R0, asm.Half),
		asm.LoadMem(asm.R0, asm.R6, tpSport, asm.Half),
		asm.StoreMem(asm.RFP, rec(28), asm.R0, asm.Half),
		asm.LoadMem(asm.R0, asm.R6, tpDport, asm.Half),
		asm.StoreMem(asm.RFP, rec(30), asm.R0, asm.Half),
	)
	// The four addresses: bytes 32–71 of the tracepoint record are bytes
	// 32–71 of ours, copied as five 8-byte words without being interpreted.
	for off := int16(tpAddrs); off < tpAddrs+40; off += 8 {
		ins = append(ins,
			asm.LoadMem(asm.R0, asm.R6, off, asm.DWord),
			asm.StoreMem(asm.RFP, rec(off), asm.R0, asm.DWord),
		)
	}

	ins = append(ins,
		// Who: only when this is connect() itself.
		asm.JNE.Imm(asm.R8, recStart, "volume"),
		asm.FnGetCurrentPidTgid.Call(), // tgid in the upper half: the process, not the thread
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, rec(16), asm.R0, asm.Word),
		asm.FnGetCurrentUidGid.Call(), // uid in the lower half
		asm.StoreMem(asm.RFP, rec(20), asm.R0, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(rec(72))),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)

	// How much it moved: only at the close, and only when the offsets of the
	// counters in this kernel's struct tcp_sock are known.
	volume := asm.Instructions{asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("volume")} // a no-op to carry the label
	if vol != nil {
		volume = asm.Instructions{
			asm.JNE.Imm(asm.R8, recClosed, "emit").WithSymbol("volume"),
			asm.LoadMem(asm.R9, asm.R6, tpSkaddr, asm.DWord), // the socket is a struct tcp_sock
		}
		for _, f := range []struct {
			dst int16
			off int32
		}{{rec(88), vol.sent}, {rec(96), vol.recv}} {
			volume = append(volume,
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, int32(f.dst)),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R3, asm.R9),
				asm.Add.Imm(asm.R3, f.off),
				asm.FnProbeReadKernel.Call(),
			)
		}
	}
	ins = append(ins, volume...)

	ins = append(ins,
		// bpf_ringbuf_output(events, &record, 104, 0)
		asm.LoadMapPtr(asm.R1, eventsFD).WithSymbol("emit"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(recBase)),
		asm.Mov.Imm(asm.R3, kernelRecordSize),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),

		// The buffer was full: count the record we could not queue.
		asm.StoreImm(asm.RFP, keySlot, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, dropsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(keySlot)),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return ins
}
