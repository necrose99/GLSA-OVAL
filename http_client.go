package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// fetchPage fetches the page content from a given URL
func fetchPage(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching page %s: %v", url, err)
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
	body, err := fetchPage(url)
	if err != nil {
		return 0, err
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("error parsing HTML for CVSS score page %s: %v", cveID, err)
	}

	cvssScoreStr := doc.Find(`[data-testid="vuln-cvssv3-base-score"]`).Text()
	if cvssScoreStr == "" {
		return 0, fmt.Errorf("CVSS score not found for %s", cveID)
	}

	cvssScore, err := strconv.ParseFloat(cvssScoreStr, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing CVSS score for %s: %v", cveID, err)
	}

	return cvssScore, nil
}
