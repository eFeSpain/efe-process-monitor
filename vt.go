package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// VirusTotal free tier allows 4 requests/minute. A shared token bucket throttles
// both file-hash and IP lookups so we don't burn the quota in a burst.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64 // tokens per second
	last   time.Time
}

func newBucket(max, perMin float64) *tokenBucket {
	return &tokenBucket{tokens: max, max: max, rate: perMin / 60, last: time.Now()}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

var vtBucket = newBucket(4, 4) // 4 burst, refills at 4/min

// Background resolution queue for uncached file hashes, so page renders never
// block on VirusTotal. Results land in SQLite and show up on the next refresh.
var (
	vtQueue   = make(chan string, 4000)
	vtPending sync.Map // hash -> struct{} to avoid duplicate enqueues
)

func enqueueHash(h string) {
	if _, loaded := vtPending.LoadOrStore(h, struct{}{}); loaded {
		return
	}
	select {
	case vtQueue <- h:
	default:
		vtPending.Delete(h) // queue full; let a later render re-enqueue
	}
}

func vtWorker() {
	for h := range vtQueue {
		for !vtBucket.allow() { // wait for a token (4/min)
			time.Sleep(time.Second)
		}
		resolveHash(h)
		vtPending.Delete(h)
	}
}

// resolveHash queries VT for a hash and persists the verdict. 404 (unknown to
// VT) is cached as NOT_IN_VT so we never ask again; 429/errors are left to retry.
func resolveHash(h string) {
	if getVTKey() == "" {
		return
	}
	var resp struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	err := getJSON("https://www.virustotal.com/api/v3/files/"+h,
		map[string]string{"x-apikey": getVTKey()}, &resp)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			dbSaveHash(h, "NOT_IN_VT")
		}
		return // 429 / transient: leave uncached so it retries
	}
	dbSaveHash(h, fmt.Sprintf("%d/%d", resp.Data.Attributes.Stats.Malicious,
		resp.Data.Attributes.Stats.Undetected))
}
