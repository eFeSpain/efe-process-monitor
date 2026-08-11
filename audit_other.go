//go:build !linux && !windows

package main

// Rootkit cross-view probes are not implemented on this OS.
//
// The second return value exists precisely so this case cannot be mistaken for a
// clean result: returning a bare nil made the audit print "no discrepancies
// between process sources", which is a confident pass for a check that never ran.
// In a security audit that is the worst possible output.
func hiddenProcs(lang string) ([]string, bool) { return nil, false }
func promiscIfaces() ([]string, bool)          { return nil, false }
