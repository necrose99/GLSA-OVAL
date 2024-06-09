package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/puerkitoBio/goquery"
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

func generateOVALDefinitions(doc *goquery.Document) (*oval.Definitions, error) {
	definitions := &oval.Definitions{}

	doc.Find(".glsa-item").Each(func(i int, s *goquery.Selection) {
		id := s.Find("h2").Text()
		advisoryLink, exists := s.Find("h2 a").Attr("href")
		if not exists {
			fmt.Printf("No advisory link found for %s\n", id)
			return
		}

		cveRefs, err := extractCVERefsFromPage("https://security.gentoo.org" + advisoryLink)
		if err != nil {
			fmt.Printf("Error extracting CVE references for %s: %v\n", id, err)
			return
		}

		definition := &oval.Definition{
			ID:          id,
			Description: "Vulnerability description",
			Advisory:    &oval.Advisory{},
			Metadata: &oval.Metadata{
				References: []oval.Reference{
					{
						Source: "GENTOO_SECURITY_ADVISORY",
						RefID:  "GLSA-" + id,
						RefURL: "https://security.gentoo.org/glsa",
					},
				},
			},
		}

		for _, ref := range cveRefs {
			definition.Advisory.Refs = append(definition.Advisory.Refs, oval.Reference{RefID: ref})
		}

		test := &oval.Test{
			ID:      fmt.Sprintf("%s-test", id),
			Comment: "Check for vulnerable package",
			Object:  &oval.Object{Comment: fmt.Sprintf("%s-obj", id)},
			State:   &oval.State{Comment: fmt.Sprintf("%s-state", id)},
		}

		definition.Tests = []*oval.Test{test}
		definitions.Definitions = append(definitions.Definitions, definition)
	})

	return definitions, nil
}
