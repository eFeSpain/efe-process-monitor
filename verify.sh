#!/usr/bin/env bash
# Run locally what CI runs, in the same order, plus the two things CI cannot do
# from a single runner: cross-compile every release target, and execute the test
# binary on Linux from a Windows checkout.
#
# This exists because "it passes on my machine" kept meaning "it passes the subset
# of the gates I happened to run". Every tool below has caught a real defect that
# the others did not:
#   gofmt/vet    formatting and obvious mistakes
#   test -race   data races on the settings shared with background goroutines
#   staticcheck  dead code
#   gosec        an unbounded PID conversion, an unescaped template value
#   linux run    a GOOS-dependent filepath.Base that made a detection rule dead
#
# Usage:  ./verify.sh            full run
#         ./verify.sh --quick    skip cross-compile and the WSL Linux run
set -uo pipefail

cd "$(dirname "$0")"
fail=0
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32mOK\033[0m %s\n' "${1:-}"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "${1:-}"; fail=1; }

# Tools that are not part of the Go distribution. Installed on demand so a fresh
# checkout can run this without a separate setup step.
tool() { # tool <binary> <go-install-path>
  local bin="$(go env GOPATH)/bin/$1"
  [ -x "$bin" ] || [ -x "$bin.exe" ] || {
    printf '   installing %s…\n' "$1"
    go install "$2" >/dev/null 2>&1 || { bad "could not install $1"; return 1; }
  }
  return 0
}

step "gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then bad "not gofmt-clean:"; echo "$unformatted"; else ok; fi

step "go vet"
if go vet ./...; then ok; else bad; fi

step "go test -race"
# -v so the pass count is available; the output goes to a log either way.
if go test -race -v ./... >/tmp/verify-test.log 2>&1; then
  ok "$(grep -c '^--- PASS' /tmp/verify-test.log) tests"
else
  bad; grep -E '^(--- FAIL|\s+--- FAIL|FAIL|.*\.go:[0-9]+:)' /tmp/verify-test.log | head -30
fi

step "staticcheck"
if tool staticcheck honnef.co/go/tools/cmd/staticcheck@latest; then
  if "$(go env GOPATH)/bin/staticcheck" ./...; then ok; else bad; fi
fi

step "gosec"
# Keep these arguments identical to .github/workflows/ci.yml, or this step stops
# meaning anything.
if tool gosec github.com/securego/gosec/v2/cmd/gosec@latest; then
  if "$(go env GOPATH)/bin/gosec" -quiet -exclude-generated -severity medium \
      -exclude=G101 \
      '-exclude-rules=audit\.go:G304,G703;lan\.go:G304;proc\.go:G204,G702;tools/.*:G115,G304,G306' \
      ./...; then ok; else bad; fi
fi

if [ "${1:-}" = "--quick" ]; then
  printf '\n(quick mode: skipped cross-compile and the Linux run)\n'
  [ "$fail" -eq 0 ] && { printf '\033[32mall green\033[0m\n'; exit 0; }
  printf '\033[31mfailures above\033[0m\n'; exit 1
fi

step "cross-compile (release targets)"
for t in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${t%/*}; arch=${t#*/}
  if CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o /dev/null . 2>/tmp/verify-build.log; then
    ok "$t"
  else
    bad "$t"; cat /tmp/verify-build.log
  fi
done

# CI runs the suite on Linux; a Windows-only local run misses anything
# platform-dependent. WSL is enough to catch that class without a second machine.
step "run the test suite on Linux"
if command -v wsl >/dev/null 2>&1; then
  if CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o ./efemon-linux.test . 2>/dev/null; then
    # Translate C:/path into /mnt/c/path for WSL. Done here rather than with
    # wslpath so the whole command stays a single quoted string.
    win="$(pwd -W 2>/dev/null || pwd)"
    drive="$(printf '%s' "$win" | cut -c1 | tr 'A-Z' 'a-z')"
    wsldir="/mnt/$drive$(printf '%s' "$win" | cut -c3-)"
    # -race needs cgo, which a cross-compiled binary does not have; this run is
    # for logic that differs by platform, not for races.
    out=$(wsl -- bash -c "cd '$wsldir' && cp efemon-linux.test /tmp/efemon.test && \
      chmod +x /tmp/efemon.test && cd /tmp && ./efemon.test -test.count=1 2>&1 | tail -20")
    if printf '%s' "$out" | grep -q '^PASS'; then ok "(no -race: needs cgo)"; else bad; printf '%s\n' "$out"; fi
    rm -f ./efemon-linux.test
  else
    bad "could not build the Linux test binary"
  fi
else
  printf '   \033[33mSKIP\033[0m wsl not available; CI will be the first Linux run\n'
fi

if [ "$fail" -eq 0 ]; then printf '\n\033[32mall green\033[0m\n'; exit 0; fi
printf '\n\033[31mfailures above\033[0m\n'; exit 1
