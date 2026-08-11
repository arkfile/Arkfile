package config

// Version is the release version string (for example v1.26.8).
// Build scripts inject the value used at link time via -ldflags -X.
var Version = "v1.26.8"

// GitCommit is the short hash of the pushed commit underlying this build.
// Build scripts inject it via -ldflags -X; defaults to "unknown" when unset.
var GitCommit = "unknown"
