#!/usr/bin/env bash
# Runs the kernel tests (TestKernel…) as root without being root: boots this
# machine's kernel in a throwaway QEMU/KVM virtual machine whose only process
# is the test binary. Nothing on the host is touched; the eBPF program is
# loaded into the VM's kernel, verified by it, and sees real TCP connections
# over the VM's loopback.
#
#   scripts/vm-kernel-test.sh            all kernel tests
#   scripts/vm-kernel-test.sh Outbound   only tests matching ^TestKernel.*Outbound
#
# Exit status: 0 passed, 1 failed, 2 cannot run here (no QEMU/KVM/kernel image).
set -euo pipefail
cd "$(dirname "$0")/.."

kernel="/boot/vmlinuz-$(uname -r)"
skip() { echo "vm-kernel-test: skipped — $1" >&2; exit 2; }
[ "$(uname -m)" = x86_64 ] || skip "only wired up for x86_64"
command -v qemu-system-x86_64 >/dev/null || skip "qemu-system-x86_64 not installed"
command -v cpio >/dev/null || skip "cpio not installed"
[ -r "$kernel" ] || skip "$kernel is not readable"
[ -w /dev/kvm ] || skip "/dev/kvm is not writable (add yourself to the kvm group)"

pattern="^TestKernel${1:+.*$1}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/root"

# The test binary is /init: statically linked, no libc, no shell needed.
CGO_ENABLED=0 go test -c -o "$tmp/root/init" .
(cd "$tmp/root" && find . | cpio -o -H newc --quiet) > "$tmp/initramfs.cpio"

set +e
timeout 180 qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -nographic -no-reboot \
  -kernel "$kernel" -initrd "$tmp/initramfs.cpio" \
  -append "console=ttyS0 quiet panic=-1 -- -test.run=$pattern -test.v" \
  2>&1 | tr -d '\r' | tee "$tmp/out.log" | grep -a -v '^$' | sed -n '/^=== RUN\|^--- \|^    \|^PASS\|^FAIL\|^ok\|^VMTEST\|^panic\|^\t/p'
set -e

if grep -a -q '^VMTEST: exit 0' "$tmp/out.log"; then
  echo "vm-kernel-test: passed ($(uname -r))"
  exit 0
fi
echo "vm-kernel-test: FAILED — full console output follows" >&2
cat "$tmp/out.log" >&2
exit 1
