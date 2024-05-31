package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

// fetchPage fetches the page content from a given URL
func fetchPage(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching page: %v", err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading page content: %v", err)
	}

	return string(body), nil
}

// fetchCVSSScore fetches and parses the CVSS score for a given CVE
func fetchCVSSScore(cveID string) (float64, error) {
	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	res, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("error fetching CVSS score for %s: %v", cveID, err)
	}
	defer res.Body.Close()

	doc, err := htmlquery.Parse(res.Body)
	if err != nil {
		return 0, fmt.Errorf("error parsing HTML for CVSS score page %s: %v", cveID, err)
	}

	// Example XPath expression to find CVSS score
	xpathExpr := `//span[@data-testid="vuln-cvssv3-base-score"]/text()`
	node := htmlquery.FindOne(doc, xpathExpr)
	if node == nil {
		return 0, fmt.Errorf("CVSS score not found for %s", cveID)
	}

	cvssScoreStr := htmlquery.InnerText(node)
	cvssScore, err := strconv.ParseFloat(cvssScoreStr, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing CVSS score for %s: %v", cveID, err)
	}

	return cvssScore, nil
}
