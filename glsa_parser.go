package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/antchfx/htmlquery"
	"github.com/pandatix/go-cvss/31"
	"github.com/quay/goval-parser/oval"
	"github.com/umisama/go-cvss/v3"
)

// extractCVERefsFromPage extracts CVE references from a GLSA advisory page
func extractCVERefsFromPage(url string) ([]string, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching page %s: %v", url, err)
	}
	defer res.Body.Close()

	doc, err := htmlquery.Parse(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML for page %s: %v", url, err)
	}

	cveRefs := make([]string, 0)
	cveRegex := regexp.MustCompile(`CVE-\d{4}-\d+`)

	xpathExpr := `//div[@class="glsa-description"]//text()`
	nodes := htmlquery.Find(doc, xpathExpr)

	for _, node := range nodes {
		text := strings.TrimSpace(htmlquery.InnerText(node))
		matches := cveRegex.FindAllString(text, -1)
		cveRefs = append(cveRefs, matches...)
	}

	return cveRefs, nil
}

// generateOVALDefinitions generates OVAL definitions from GLSA advisory data
func generateOVALDefinitions(doc *goquery.Document) (*oval.Definitions, error) {
	definitions := oval.NewDefinitions()

	doc.Find(".glsa-item").Each(func(i int, s *goquery.Selection) {
		id := s.Find("h2").Text()
		advisoryLink, exists := s.Find("h2 a").Attr("href")
		if !exists {
			fmt.Printf("No advisory link found for %s\n", id)
			return
		}

		cveRefs, err := extractCVERefsFromPage("https://security.gentoo.org" + advisoryLink)
		if err != nil {
			fmt.Printf("Error extracting CVE references for %s: %v\n", id, err)
			return
		}

		// Create OVAL definition for this advisory
		definition := oval.NewDefinition(id, "Vulnerability description", true, nil)

		// Add CVE references to the definition
		for _, ref := range cveRefs {
			definition.References = append(definition.References, oval.Reference{RefID: ref})
		}

		// Create a test for the OVAL definition
		test := oval.NewTest(fmt.Sprintf("%s-test", id), fmt.Sprintf("%s-obj", id), fmt.Sprintf("%s-state", id), "cpe:/a:gentoo:gentoo", "Check for vulnerable package")

		// Add the test to the definition
		definition.Tests = []*oval.Test{test}

		// Append the definition to the list of definitions
		definitions.Definitions = append(definitions.Definitions, definition)
	})

	return definitions, nil
}
