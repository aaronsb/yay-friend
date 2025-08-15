package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version (set via ldflags)
	Version = "dev"
	
	// GitCommit is the git commit hash (set via ldflags)
	GitCommit = "unknown"
	
	// BuildDate is the build timestamp (set via ldflags)
	BuildDate = "unknown"
)

// String returns the full version string
func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s, %s/%s)",
		Version,
		GitCommit,
		BuildDate,
		runtime.GOOS,
		runtime.GOARCH,
	)
}

// Short returns just the version and commit
func Short() string {
	if len(GitCommit) > 7 {
		return fmt.Sprintf("%s (%s)", Version, GitCommit[:7])
	}
	return fmt.Sprintf("%s (%s)", Version, GitCommit)
}