package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

// ouidata.gz is the merged IEEE OUI → vendor table (MA-L/MA-M/MA-S), regenerated
// with `go run ./tools/genoui`. Embedded so vendor lookups are fully offline.
// Keys are variable-length prefixes: 6 hex (/24), 7 hex (/28) or 9 hex (/36).
//
//go:embed ouidata.gz
var ouiGz []byte

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
)

// loadOUI lazily decompresses the embedded table on first lookup.
func loadOUI() {
	ouiTable = make(map[string]string, 40000)
	zr, err := gzip.NewReader(bytes.NewReader(ouiGz))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if prefix, name, ok := strings.Cut(sc.Text(), "\t"); ok {
			ouiTable[prefix] = name
		}
	}
}

// ouiVendor returns the registered vendor for a MAC's OUI prefix, or "" if the
// MAC is empty, locally administered, or unknown to the IEEE registry.
func ouiVendor(mac string) string {
	if mac == "" {
		return ""
	}
	hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(hex) < 6 {
		return ""
	}
	// Locally administered addresses (2nd-least-significant bit of 1st octet set)
	// have no IEEE owner; skip them rather than report a misleading vendor.
	if b := fromHex(hex[1]); b >= 0 && b&0x2 != 0 {
		return ""
	}
	ouiOnce.Do(loadOUI)
	// Longest-prefix match: MA-S (/36, 9 hex) → MA-M (/28, 7 hex) → MA-L (/24, 6 hex).
	for _, n := range [3]int{9, 7, 6} {
		if len(hex) >= n {
			if v, ok := ouiTable[hex[:n]]; ok {
				return v
			}
		}
	}
	return ""
}

// fromHex returns the value of a single hex digit, or -1 if invalid.
func fromHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}
