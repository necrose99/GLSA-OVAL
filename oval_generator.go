package main

import (
	"fmt"
	"log"

	"github.com/quay/goval-parser/oval"
)

// writeOVALDefinitionsToFile writes OVAL definitions to an XML file
func writeOVALDefinitionsToFile(definitions *oval.Definitions, filename string) error {
	xmlData, err := definitions.ToXML()
	if err != nil {
		return fmt.Errorf("error converting definitions to XML: %v", err)
	}

	if err := ioutil.WriteFile(filename, xmlData, 0644); err != nil {
		return fmt.Errorf("error writing definitions to file: %v", err)
	}

	return nil
}

// GenerateOVALDefinitions generates OVAL definitions and writes them to a file
func GenerateOVALDefinitions() {
	definitions, err := generateOVALDefinitions(doc)
	if err != nil {
		log.Fatalf("Error generating OVAL definitions: %v", err)
	}

	if err := writeOVALDefinitionsToFile(definitions, "GLSA.oval"); err != nil {
		log.Fatalf("Error writing OVAL definitions to file: %v", err)
	}
}
