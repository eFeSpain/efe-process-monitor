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
// O_EXCL is not used: the file is rewritten on every start by design. The mode is
// applied at creation by the kernel, so unlike the Windows path there is no window
// where the file exists with wider permissions.
func writeSecretFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return secureFile(path)
}
