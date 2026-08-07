package config

// Version is the release version string (for example v1.26.8).
// Build scripts inject the value used at link time via -ldflags -X.
var Version = "v1.26.8"

// GitCommit is the short git commit hash from the build that produced this binary.
// Build scripts inject it via -ldflags -X; defaults to "unknown" when unset.
var GitCommit = "unknown"
