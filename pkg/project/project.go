package project

var (
	buildTimestamp = ""
	gitSHA         = ""
	version        = "0.4.1"
)

// BuildTimestamp returns the build time, injected at build time via ldflags.
func BuildTimestamp() string {
	return buildTimestamp
}

// GitSHA returns the git commit the binary was built from, injected at build
// time via ldflags.
func GitSHA() string {
	return gitSHA
}

// Version returns the semantic version, injected at build time via ldflags.
// It falls back to a development placeholder for local builds.
func Version() string {
	return version
}
