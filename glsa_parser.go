package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"os"
	"github.com/PuerkitoBio/goquery"
	"github.com/quay/goval-parser/oval"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type GLSAParser struct {
	baseURL string
	client  *http.Client
}

func NewGLSAParser(baseURL string) *GLSAParser {
	return &GLSAParser{
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

func (p *GLSAParser) ScrapeGLSAs() error {
	glsaURL := p.baseURL + "/glsa"
	doc, err := p.fetchAndParseHTML(glsaURL)
	if err != nil {
		return err
	}

	glsaLinks, err := extractGLSALinks(doc)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	resultChan := make(chan *ovalparser.OvalDefinitions, len(glsaLinks))

	for _, link := range glsaLinks {
		glsaPageURL := p.baseURL + link
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			ovalDefinitions, err := p.parseGLSAPage(url)
			if err != nil {
				log.Printf("Error parsing GLSA page %s: %v", url, err)
				return
			}
			resultChan <- ovalDefinitions
		}(glsaPageURL)
	}

	wg.Wait()
	close(resultChan)

	for ovalDefinitions := range resultChan {
		ovalXML, err := xml.MarshalIndent(ovalDefinitions, "", "  ")
		if err != nil {
			log.Printf("Error generating OVAL XML: %v", err)
			continue
		}
		saveOvalXML(ovalXML)
	}

	return nil
}

func (p *GLSAParser) fetchAndParseHTML(url string) (*goquery.Document, error) {
	resp, err := p.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func extractGLSALinks(doc *goquery.Document) ([]string, error) {
	var links []string
	doc.Find("a[href*='/glsa/']").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			links = append(links, href)
		}
	})
	return links, nil
}

func (p *GLSAParser) parseGLSAPage(glsaPageURL string) (*ovalparser.OvalDefinitions, error) {
	doc, err := p.fetchAndParseHTML(glsaPageURL)
	if err != nil {
		return nil, err
	}

	affectedPackages, err := extractAffectedPackages(doc)
	if err != nil {
		return nil, err
	}

	resolutionSteps, err := extractResolutionSteps(doc)
	if err != nil {
		return nil, err
	}

	cveReferences, err := extractCVEReferences(doc)
	if err != nil {
		return nil, err
	}

	ovalDescription := "Description of the vulnerability"
	ovalDefinitions, err := generateOvalXML(glsaPageURL, affectedPackages, resolutionSteps, cveReferences, ovalDescription)
	if err != nil {
		return nil, err
	}

	return ovalDefinitions, nil
}

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

// extractCVEReferences extracts CVE references from a given advisory page.
func extractCVEReferences(doc *goquery.Document) ([]oval.CveReference, error) {
	var cveReferences []oval.CveReference

	doc.Find("h3:contains('References')").NextUntil("h3").Find("a[href*='/CVE-']").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		cveID := strings.TrimPrefix(strings.TrimPrefix(href, "https://cve.mitre.org/cgi-bin/cvename.cgi?name="), "CVE-")
		cveDescription := s.Text()

		cvss, version, err := parseCVSS(cveDescription)
		if err != nil {
			log.Printf("Error parsing CVSS vector for %s: %v", cveID, err)
			return
		}

		cveReferences = append(cveReferences, oval.CveReference{
			CveID:       cveID,
			Description: cveDescription,
			CvssVersion: version,
			CvssScore:   cvss,
		})
	})

	return cveReferences, nil
}

// Other functions for extracting affected packages, resolution steps,
// generating OVAL XML, and saving OVAL XML go here...

func main() {
	parser := NewGLSAParser("https://security.gentoo.org")
	if err := parser.ScrapeGLSAs(); err != nil {
		log.Fatalf("Error scraping GLSAs: %v", err)
	}
}
[

)
// glsa-oval.xml fix to add glsa-oval-date-24hourtime.xml"
func saveOvalXML(ovalXML []byte) error {
    filename := "glsa-oval.xml"
    return os.WriteFile(filename, ovalXML, 0644)
}
]