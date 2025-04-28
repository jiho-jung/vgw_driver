package lsmod

// LsMod is a function reading and parsing procModulesFile pseudo-file
func LsMod(procModulesFile string) (map[string]ModInfo, error) {
	return parse(procModulesFile)
}
