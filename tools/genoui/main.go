// Command genoui builds the embedded OUI → vendor table from the IEEE registry.
//
// It merges the three IEEE assignment files — MA-L (/24, 6 hex), MA-M (/28, 7 hex)
// and MA-S (/36, 9 hex) — into one gzip-compressed "PREFIX\tVendor" table that
// lan.go embeds via go:embed, so vendor lookups are fully offline and add no
// runtime network calls. ouiVendor does a longest-prefix match (9→7→6 hex).
//
// Usage (run from the go/ module root):
//
//	go run ./tools/genoui                                  # downloads all three
//	go run ./tools/genoui -in oui_raw.csv,mam_raw.csv,mas_raw.csv -out ouidata.gz
package main

import (
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// IEEE assignment files. Each lives under its own path and uses an assignment
// field of a different hex length (6/7/9), which is what encodes the block size.
var ieeeURLs = []string{
	"https://standards-oui.ieee.org/oui/oui.csv",     // MA-L /24
	"https://standards-oui.ieee.org/oui28/mam.csv",   // MA-M /28
	"https://standards-oui.ieee.org/oui36/oui36.csv", // MA-S /36
}

// validLen is the set of accepted assignment prefix lengths (hex chars).
var validLen = map[int]bool{6: true, 7: true, 9: true}

// placeholders are registry names that carry no real vendor; for subdivided
// blocks the parent /24 is registered to "IEEE Registration Authority" and the
// real owner is in the MA-M/MA-S file, so skipping these lets the longer prefix win.
var placeholders = map[string]bool{
	"ieee registration authority": true,
}

func main() {
	in := flag.String("in", "", "comma-separated IEEE csv paths (downloads all three if empty)")
	out := flag.String("out", "ouidata.gz", "output gzip file")
	flag.Parse()

	var srcs []io.ReadCloser
	if *in != "" {
		for _, p := range strings.Split(*in, ",") {
			f, err := os.Open(strings.TrimSpace(p))
			if err != nil {
				log.Fatalf("open %s: %v", p, err)
			}
			srcs = append(srcs, f)
		}
	} else {
		c := &http.Client{Timeout: 90 * time.Second}
		for _, u := range ieeeURLs {
			log.Printf("downloading %s", u)
			resp, err := c.Get(u)
			if err != nil {
				log.Fatalf("download %s: %v", u, err)
			}
			if resp.StatusCode != http.StatusOK {
				log.Fatalf("download %s: HTTP %d", u, resp.StatusCode)
			}
			srcs = append(srcs, resp.Body)
		}
	}

	table := map[string]string{}
	for _, src := range srcs {
		r := csv.NewReader(src)
		r.FieldsPerRecord = -1 // tolerate ragged rows
		rows, err := r.ReadAll()
		src.Close()
		if err != nil {
			log.Fatalf("parse csv: %v", err)
		}
		for i, rec := range rows {
			if i == 0 || len(rec) < 3 { // header / malformed
				continue
			}
			prefix := strings.ToUpper(strings.TrimSpace(rec[1]))
			if !validLen[len(prefix)] {
				continue
			}
			if placeholders[strings.ToLower(strings.TrimSpace(rec[2]))] {
				continue
			}
			if name := cleanVendor(rec[2]); name != "" {
				table[prefix] = name
			}
		}
	}
	if len(table) == 0 {
		log.Fatal("no OUI records parsed")
	}

	prefixes := make([]string, 0, len(table))
	for p := range table {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var buf strings.Builder
	for _, p := range prefixes {
		buf.WriteString(p)
		buf.WriteByte('\t')
		buf.WriteString(table[p])
		buf.WriteByte('\n')
	}

	of, err := os.Create(*out)
	if err != nil {
		log.Fatalf("create %s: %v", *out, err)
	}
	defer of.Close()
	gw, _ := gzip.NewWriterLevel(of, gzip.BestCompression)
	if _, err := io.WriteString(gw, buf.String()); err != nil {
		log.Fatalf("write: %v", err)
	}
	if err := gw.Close(); err != nil {
		log.Fatalf("flush gzip: %v", err)
	}
	fmt.Printf("wrote %s: %d vendors (%d bytes uncompressed)\n", *out, len(table), buf.Len())
}

// cleanVendor normalizes a registry organization name: collapse whitespace and
// cap length so the embedded table stays compact and the UI label stays short.
func cleanVendor(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 48 {
		s = strings.TrimSpace(s[:48])
	}
	return s
}
