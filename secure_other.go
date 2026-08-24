//go:build !windows

package main

import (
	"fmt"
	"os"
)

// On Unix the file mode is the mechanism, and os.WriteFile already honours it, so
// there is nothing extra to do. The explicit Chmod covers the case where the file
// already existed with wider permissions — WriteFile does not narrow an existing
// file's mode.
func secureFile(path string) error {
	return os.Chmod(path, 0o600)
}

// describeFileACL reports the mode, for the startup banner.
func describeFileACL(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "desconocida"
	}
	return fmt.Sprintf("modo %#o", fi.Mode().Perm())
}

// writeSecretFile writes data with owner-only permissions.
//
// Delegates to writeFileAtomic, which creates a temp file, restricts it, and only
// then renames it into place — so the secret never exists at its real path with
// wider permissions, and a crash mid-write cannot truncate it.
func writeSecretFile(path string, data []byte) error {
	return writeFileAtomic(path, data, 0o600)
}
