package daemon

import "runtime/debug"

// Version is the daemon's version. Release builds set it with
//
//	-ldflags "-X github.com/aghman/openaim/internal/daemon.Version=v0.1.0"
var Version = ""

// BuildVersion is Version, else the module version Go recorded at build
// time, else "dev".
func BuildVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
