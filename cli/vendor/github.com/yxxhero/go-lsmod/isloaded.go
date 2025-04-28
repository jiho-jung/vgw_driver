package lsmod

import (
	"path/filepath"
)

// IsLoaded just check if the specified module loaded
func IsLoaded(hostRoot, name string) (bool, error) {
	procModulesFile := filepath.Join(hostRoot, "proc", "modules")
	mods, err := LsMod(procModulesFile)
	if err != nil {
		return false, err
	}

	info, ok := mods[name]

	if !ok {
		return false, nil
	}

	return info.Instances > 0 && info.State == StateLive, nil
}
