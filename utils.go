// utils.go
// misc go utils functions
// offer glsa-oval.xml > to packing for publishing vulnerabilities glsa-oval.xml.xz

//The software is not affected by the supply chain attack on the original xz implementation ie gxz or library... 

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/ulikunitz/xz"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func utils() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Do you want to compress glsa-oval.xml to glsa-oval.xml.xz? (Y/N): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(answer)

	if strings.ToUpper(answer) != "Y" {
		fmt.Println("Exiting without compression.")
		return
	}

	// Open input file
	file, err := os.Open("glsa-oval.xml")
	if err != nil {
		log.Fatalf("Error opening input file: %v", err)
	}
	defer file.Close()

	// Create output file
	outFile, err := os.Create("glsa-oval.xml.xz")
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer outFile.Close()

	// Create xz writer
	w, err := xz.NewWriter(outFile)
	if err != nil {
		log.Fatalf("Error creating xz writer: %v", err)
	}
	defer w.Close()

	// Copy contents from input file to xz writer
	_, err = io.Copy(w, file)
	if err != nil {
		log.Fatalf("Error copying data: %v", err)
	}

	fmt.Println("Compression completed: glsa-oval.xml > glsa-oval.xml.xz")
}
