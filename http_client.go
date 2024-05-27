package main

import (
	"fmt"
	"net/http"
	"log"

	"github.com/antchfx/htmlquery"
	cvss "github.com/umisama/go-cvss/v3"
)

// Fetches the HTML content from a given URL and returns the parsed document
func fetchHTML(url string) (*htmlquery.Node, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching page %s: %v", url, err)
	}
	defer res.Body.Close()

	doc, err := htmlquery.Parse(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML for page %s: %v", url, err)
	}

	return doc, nil
}

// Fetches CVSS score from NVD for a given CVE ID
func fetchCVSSFromNVD(cveID string) (string, error) {
	nvdURL := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	doc, err := fetchHTML(nvdURL)
	if err != nil {
		return "", err
	}

	// Adjust the XPath expression according to the NVD page structure
	cvssNode := htmlquery.FindOne(doc, `//span[@data-testid='vuln-cvssv3-base-score']`)
	if cvssNode == nil {
		return "", fmt.Errorf("CVSS score not found for %s", cveID)
	}

	cvssScore := htmlquery.InnerText(cvssNode)
	return cvssScore, nil
}

// Parses a CVSS score string into a CVSS object
func parseCVSS(cvssString string) (*cvss.Vectors, error) {
	parsedCVSS, err := cvss.Parse(cvssString)
	if err != nil {
		return nil, fmt.Errorf("error parsing CVSS score: %v", err)
	}
	return &parsedCVSS, nil
}

// Fetches CVSS scores for all CVEs in the given data
func fetchCVSSFromNVDForAll(cveData map[string][]string) error {
	for cveID := range cveData {
		cvssScore, err := fetchCVSSFromNVD(cveID)
		if err != nil {
			log.Printf("Error fetching CVSS score for %s: %v", cveID, err)
			continue
		}

		parsedCVSS, err := parseCVSS(cvssScore)
		if err != nil {
			log.Printf("Error parsing CVSS score for %s: %v", cveID, err)
			continue
		}

		fmt.Printf("CVSS score for %s: %v\n", cveID, parsedCVSS)
	}
	return nil
}
