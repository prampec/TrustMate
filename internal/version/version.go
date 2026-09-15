// Package version holds the application's release version, set at build
// time via -ldflags "-X .../internal/version.Version=vX.Y.Z". Binaries
// built without that flag (go build, go run) report "dev".
package version

var Version = "dev"
