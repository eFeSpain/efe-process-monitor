//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
)

// secureFile restricts a file to the smallest set of principals that still lets
// this process use it.
//
// Why an explicit ACL is required: os.WriteFile's 0600 is a no-op on Windows. Go
// maps the mode to the read-only attribute and nothing else, so the file simply
// inherits the directory's ACL — which for anything under the user's profile
// grants that user full control. The token file was therefore readable by any
// process running as the user, which is exactly the principal the local gate is
// meant to keep out.
//
// Why the ACL depends on elevation: on Windows, elevating does *not* change your
// SID. An elevated and a non-elevated process of the same account share it, so
// granting "the current user" would leave the hole open. What differs is the
// token: in a non-elevated process the Administrators group is present but marked
// deny-only, so it cannot be used to gain access. Granting only Administrators
// and SYSTEM is therefore what actually separates the two.
//
//	elevated     → Administrators + SYSTEM. A non-elevated same-user process is
//	               refused, which closes the escalation path.
//	not elevated → the current user only. Cannot do better (we would lock
//	               ourselves out), but other users of the machine are still shut
//	               out, which is the equivalent of 0600 on Unix.
func secureFile(path string) error {
	args := []string{path, "/inheritance:r"}
	if elevated {
		// *SID form so this works on any system language.
		args = append(args,
			"/grant:r", "*S-1-5-32-544:F", // BUILTIN\Administrators
			"/grant:r", "*S-1-5-18:F") // NT AUTHORITY\SYSTEM
	} else {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("no se pudo determinar el usuario actual: %w", err)
		}
		// The "*" prefix tells icacls the principal is a SID rather than a name;
		// without it the call fails with "no mapping between account names and
		// security IDs". user.Current().Uid is the SID string on Windows.
		args = append(args, "/grant:r", "*"+u.Uid+":F")
	}
	out, err := command("icacls", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// describeFileACL returns the current ACL, for the startup banner and for
// diagnosing a machine where the lockdown did not take.
func describeFileACL(path string) string {
	out, err := command("icacls", path).Output()
	if err != nil {
		return "desconocida"
	}
	var who []string
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		// Lines look like: "<path> BUILTIN\Administrators:(F)" then continuations.
		if i := strings.LastIndex(ln, ":("); i > 0 {
			entry := ln[:i]
			if j := strings.LastIndexAny(entry, " \t"); j >= 0 {
				entry = entry[j+1:]
			}
			if entry != "" && !strings.Contains(entry, `\`+path) {
				who = append(who, entry)
			}
		}
	}
	if len(who) == 0 {
		return "desconocida"
	}
	return strings.Join(who, ", ")
}

// writeSecretFile writes data and then locks the file down.
//
// The order matters and is not ideal: there is a brief window between creation
// and the ACL being applied. Closing it properly means creating the handle with a
// security descriptor already attached (CreateFileW with SECURITY_ATTRIBUTES),
// which Go's os package does not expose. The window is one syscall wide on a file
// whose name an attacker must already be racing, and the alternative is hand-rolled
// syscall code in the startup path; documented rather than pretended away.
func writeSecretFile(path string, data []byte) error {
	// Remove any pre-existing file first: if a previous elevated run locked it to
	// Administrators and this run is not elevated, the write below would fail and
	// leave a stale token in place.
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			log.Printf("[!] no se pudo eliminar %s antes de reescribirlo: %v", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return secureFile(path)
}
