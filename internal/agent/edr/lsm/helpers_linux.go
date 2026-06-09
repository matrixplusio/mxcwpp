//go:build linux

package lsm

import "os"

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func containsBytes(data, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(data); i++ {
		match := true
		for j := range needle {
			if data[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
