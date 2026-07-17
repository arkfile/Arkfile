package flags

// PopBool removes every occurrence of flagName from args and reports whether it
// was present. Use before flag.Parse when trailing positionals would otherwise
// prevent Go's flag package from seeing the boolean flag.
func PopBool(args []string, flagName string) ([]string, bool) {
	found := false
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == flagName {
			found = true
			continue
		}
		out = append(out, arg)
	}
	return out, found
}
