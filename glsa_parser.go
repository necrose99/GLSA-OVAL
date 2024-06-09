package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/puerkitoBio/goquery"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
	"github.com/quay/goval-parser/oval"
)

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

func determineCVSSVersion(cvssString string) (interface{}, string, error) {
	switch {
	default: // Should be CVSS v2.0 or is invalid
		cvss, err := gocvss20.ParseVector(cvssString)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CVSS vector: %s", cvssString)
		}
		return cvss, "CVSS 2.0", nil
	case strings.HasPrefix(cvssString, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(cvssString)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CVSS vector: %s", cvssString)
		}
		return cvss, "CVSS 3.0", nil
	case strings.HasPrefix(cvssString, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(cvssString)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CVSS vector: %s", cvssString)
		}
		return cvss, "CVSS 3.1", nil
	case strings.HasPrefix(cvssString, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(cvssString)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CVSS vector: %s", cvssString)
		}
		return cvss, "CVSS 4.0", nil
	}
}

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

		// Create OVAL definition for this advisory
		definition := &oval.Definition{
			ID:          id,
			Title:       "Title", // Add title if available
			Description: "Vulnerability description",
			Advisory:    oval.Advisory{},
			//Metadata:    oval.Metadata{}, // Adjust according to actual structure
		}

		// Add CVE references and fetch CVSS scores
		for _, ref := range cveRefs {
			definition.Advisory.Refs = append(definition.Advisory.Refs, oval.Reference{RefID: ref})

			// Fetch and log the CVSS score
			cvssString := "" // Replace with actual CVSS string extraction logic
			cvss, version, err := determineCVSSVersion(cvssString)
			if err != nil {
				log.Printf("Error determining CVSS version for %s: %v\n", ref, err)
			} else {
				log.Printf("CVSS version for %s: %s, CVSS data: %+v\n", ref, version, cvss)
			}
		}

		// Fetch remediation steps
		remediationSteps, err := scrapeRemediation("https://security.gentoo.org" + advisoryLink)
		if err != nil {
			log.Printf("Error fetching remediation steps for %s: %v\n", id, err)
		} else {
			definition.Description += "\n\n" + remediationSteps
		}

		// Create a test for the OVAL definition
		test := &oval.Test{
			ID:      fmt.Sprintf("%s-test", id),
			Comment: "Check for vulnerable package",
			Object:  oval.Object{Comment: fmt.Sprintf("%s-obj", id)},
			State:   oval.State{Comment: fmt.Sprintf("%s-state", id)},
		}

		// Add the test to the definition
		// definition.Tests = []oval.Test{test}

		// Append the definition to the list of definitions
		definitions.Definitions = append(definitions.Definitions, definition)
	})

	return definitions, nil
}
