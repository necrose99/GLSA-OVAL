// oval_generator.go

// # [GLSA-OVAL]
// import "path/to/oval.xsd" as xsd

package main


import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/quay/goval-parser/oval"
)

func writeOVALDefinitionsToFile(definitions *oval.Definitions, fileName string) error {
	output, err := xml.MarshalIndent(definitions, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling OVAL definitions to XML: %v", err)
	}

	if err := ioutil.WriteFile(fileName, output, 0644); err != nil {
		return fmt.Errorf("error writing OVAL definitions to file: %v", err)
	}

	return nil
}

func storeOVALDefinitions(definitions *oval.Definitions) {
	if err := writeOVALDefinitionsToFile(definitions, "GLSA-oval.xml"); err != nil {
		log.Fatalf("Error writing OVAL definitions to file: %v", err)
	}
}
