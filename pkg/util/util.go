package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// CollectInputFiles collects all pcap files from a file or directory
func CollectInputFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", input, err)
	}

	if info.IsDir() {
		return collectFromDirectory(input, true)
	}

	ext := filepath.Ext(input)
	switch ext {
	case ".pcap", ".cap", ".pcapng":
		return []string{input}, nil
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

// collectFromDirectory recursively finds all pcap/cap/pcapng files
func collectFromDirectory(dir string, recursive bool) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != dir && !recursive {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".pcap" || ext == ".cap" || ext == ".pcapng" {
				files = append(files, path)
			}
		}
		return nil
	})

	return files, err
}
