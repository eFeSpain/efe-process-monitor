package main

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// History search.
//
// The history modal loaded the last 500 events and filtered them in the
// browser by process name: anything older than those 500 could not be found
// at all, and "what did this address do last Tuesday" had no answer. The
// search runs in the database over everything retained — any text of the
// event, the kind, a date range — a page at a time.

const maxHistoryPage = 1000

var errBadFilter = errors.New("invalid history filter")

// parseHistTime reads a moment as a datetime-local field (or a hand-written
// URL) gives it, in local time, and how much time it names: a date is a whole
// day, a minute is a whole minute. "to" bounds are inclusive of that span.
func parseHistTime(s string) (start, end time.Time, err error) {
	for _, l := range []struct {
		layout string
		span   func(time.Time) time.Time
	}{
		{"2006-01-02T15:04:05", func(t time.Time) time.Time { return t.Add(time.Second) }},
		{"2006-01-02T15:04", func(t time.Time) time.Time { return t.Add(time.Minute) }},
		// AddDate, not +24 h: the day the clocks change is not 24 hours long.
		{"2006-01-02", func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
	} {
		if t, e := time.ParseInLocation(l.layout, s, time.Local); e == nil {
			return t, l.span(t), nil
		}
	}
	return start, end, errBadFilter
}

// parseEventFilter reads the history filter from a request's query string:
// q, kind, process, from, to, before, limit. Anything present but not
// understood is an error — the caller must not act on a filter that was
// silently widened.
func parseEventFilter(r *http.Request) (eventFilter, error) {
	q := r.URL.Query()
	f := eventFilter{Text: q.Get("q"), Kind: q.Get("kind"), Process: q.Get("process")}
	if s := q.Get("from"); s != "" {
		start, _, err := parseHistTime(s)
		if err != nil {
			return f, err
		}
		f.From = float64(start.Unix())
	}
	if s := q.Get("to"); s != "" {
		_, end, err := parseHistTime(s)
		if err != nil {
			return f, err
		}
		f.To = float64(end.Unix())
	}
	if s := q.Get("before"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return f, errBadFilter
		}
		f.Before = n
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return f, errBadFilter
		}
		if n > maxHistoryPage {
			n = maxHistoryPage
		}
		f.Limit = n
	}
	return f, nil
}

// handleHistory answers a history search: {"events": [...], "next": cursor}.
// next is what to send back as "before" for the following page; 0 = no more.
func handleHistory(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	f, err := parseEventFilter(r)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"invalid filter"}`, http.StatusBadRequest)
		return
	}
	evs, next := searchEvents(f)
	if evs == nil {
		evs = []HistEvent{}
	}
	writeJSON(w, map[string]any{"events": evs, "next": next})
}
