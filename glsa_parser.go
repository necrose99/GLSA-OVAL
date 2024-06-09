package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/PuerkitoBio/goquery"
	"github.com/quay/goval-parser/oval"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// parseCVSS parses a CVSS vector string and returns the parsed CVSS object and its version.
func parseCVSS(vector string) (interface{}, string, error) {
	switch {
	default: // Should be CVSS v2.0 or is invalid
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			return nil, "", err
		}
		return cvss, "2.0", nil
	case strings.HasPrefix(vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			return nil, "", err
		}
		return cvss, "3.0", nil
	case strings.HasPrefix(vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			return nil, "", err
		}
		return cvss, "3.1", nil
	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			return nil, "", err
		}
		return cvss, "4.0", nil
	}
}

// extractCVERefsFromPage extracts CVE references from a given advisory page.
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

	// Example XPath expression to find CVE references
	xpathExpr := `//a[contains(@href, 'cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-')]/text()`
	nodes := htmlquery.Find(doc, xpathExpr)
	if nodes == nil {
		return nil, fmt.Errorf("no CVE references found")
	}

	var cveRefs []string
	for _, node := range nodes {
		cveRefs = append(cveRefs, htmlquery.InnerText(node))
	}

	return cveRefs, nil
}

// scrapeRemediation extracts remediation steps from a given advisory page.
func scrapeRemediation(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching page %s: %v", url, err)
	}
	defer res.Body.Close()

	doc, err := htmlquery.Parse(res.Body)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML for page %s: %v", url, err)
	}

	xpathExpr := `//h3[text()='Resolution']/following-sibling::div[@class='card card-body bg-light pb-0 mb-3']/pre/text()`
	nodes := htmlquery.Find(doc, xpathExpr)
	if nodes == nil {
		return "", fmt.Errorf("no remediation steps found")
	}

	var remediationSteps strings.Builder
	for _, node := range nodes {
		step := strings.TrimSpace(htmlquery.InnerText(node))
		remediationSteps.WriteString(step)
		remediationSteps.WriteString("\n")
	}

	return remediationSteps.String(), nil
}

// generateOVALDefinitions generates OVAL definitions from the GLSA page content.
func generateOVALDefinitions(doc *goquery.Document) (*oval.Definitions, error) {
	definitions := &oval.Definitions{}

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

		remediation, err := scrapeRemediation("https://security.gentoo.org" + advisoryLink)
		if err != nil {
			fmt.Printf("Error extracting remediation steps for %s: %v\n", id, err)
			return
		}

		definition := &oval.Definition{
			ID:          id,
			Description: "Vulnerability description",
			Advisory:    oval.Advisory{},
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

		definition.Advisory.Remediation = remediation

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
