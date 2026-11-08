package main

import "sync"

// lookupQueue is the "off the request path" primitive the reputation and LAN
// passes share: a render asks the cache, and on a miss hands the key here
// instead of waiting. Each key is queued at most once while its lookup is
// pending, a few workers run the lookups, and drained fires when a burst has
// been worked through — the moment to tell the page to redraw once, rather
// than once per key.
//
// VirusTotal (vt.go) and the signatures (connections.go) keep their own
// queues: one is rate-limited to a token bucket, the other batches paths into
// a single PowerShell start-up, and neither shape fits here.
type lookupQueue struct {
	ch      chan string
	pending sync.Map // key -> struct{}
}

func newLookupQueue(size int) *lookupQueue { return &lookupQueue{ch: make(chan string, size)} }

// enqueue adds key unless it is already pending. A full queue drops the key;
// the next render that misses the cache asks again.
func (q *lookupQueue) enqueue(key string) {
	if _, loaded := q.pending.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	select {
	case q.ch <- key:
	default:
		q.pending.Delete(key)
	}
}

// start runs workers goroutines that call fn for each key, then drained when
// they find the queue empty behind them. With several workers the tail of a
// burst can fire drained once per worker; the page debounces, so that is one
// redraw either way.
func (q *lookupQueue) start(workers int, fn func(key string), drained func()) {
	for i := 0; i < workers; i++ {
		go func() {
			for key := range q.ch {
				fn(key)
				q.pending.Delete(key)
				if len(q.ch) == 0 && drained != nil {
					drained()
				}
			}
		}()
	}
}

func (q *lookupQueue) isPending(key string) bool { _, ok := q.pending.Load(key); return ok }
func (q *lookupQueue) len() int                  { return len(q.ch) }

// reset empties the queue and the pending set (tests).
func (q *lookupQueue) reset() {
	for len(q.ch) > 0 {
		<-q.ch
	}
	q.pending.Range(func(k, _ any) bool { q.pending.Delete(k); return true })
}
