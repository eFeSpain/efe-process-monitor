//go:build !linux

package main

import "errors"

var errServiceUnsupported = errors.New("running as a service is not supported on this OS")

// Running as a service is a Linux (systemd) feature for now; see
// docs/superpowers/specs/2026-11-08-linux-service-design.md. These stubs keep
// the shared code compiling and let the UI report "not supported".

func serviceStatus() ServiceStatus       { return ServiceStatus{} }
func installService(fromUI bool) error   { return errServiceUnsupported }
func uninstallService() error            { return errServiceUnsupported }
func runServiceMigration()               {}
func serviceControl(action string) error { return errServiceUnsupported }
func tokenHandoffDir() string            { return appDir }
