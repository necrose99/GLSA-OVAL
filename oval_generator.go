package main

import (
	"fmt"
	"log"

	"github.com/quay/goval-parser/oval"
)

// writeOVALDefinitionsToFile writes OVAL definitions to a file
func writeOVALDefinitionsToFile(definitions *oval.Definitions, filename string) error {
	// Generate OVAL XML
	ovalXML, err := definitions.MarshalBytesXML()
	if err != nil {
		return fmt.Errorf("failed to generate OVAL XML: %v", err)
	}

	// Write OVAL XML to the specified file
	err = os.WriteFile(filename, ovalXML, 0644)
	if err != nil {
		return fmt.Errorf("error writing OVAL file: %v", err)
	}

	fmt.Println("OVAL definitions written to", filename)
	return nil
}

func main() {
	// Assuming 'definitions' is already populated with OVAL definitions

	// Write OVAL definitions to an XML file
	if err := writeOVALDefinitionsToFile(definitions, "GLSA.oval"); err != nil {
		log.Fatalf("Error writing OVAL definitions to file: %v", err)
	}
}
