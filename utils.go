package main

import (
	"fmt"
	"os"
)

// checkError checks if an error occurred and exits the program if it did
func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// checkFileExists checks if a file exists at the specified path
func checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
