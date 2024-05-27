package main

import (
	"fmt"
	"log"
)

func main() {
	// Parse GLSA advisories from Gentoo security website
	advisories, err := parseGLSAAdvisories("https://security.gentoo.org/")
	if err != nil {
		log.Fatalf("Error parsing GLSA advisories: %v", err)
	}

	// Extract CVE references from GLSA advisories
	cveData := extractCVEData(advisories)

	// Generate OVAL definitions from extracted CVE data
	definitions := generateOVALDefinitions(cveData)

	// Store OVAL definitions in a SQLite database
	if err := storeOVALDefinitionsInDB(definitions); err != nil {
		log.Fatalf("Error storing OVAL definitions in database: %v", err)
	}

	// Write OVAL definitions to an XML file
	if err := writeOVALDefinitionsToFile(definitions, "GLSA.oval"); err != nil {
		log.Fatalf("Error writing OVAL definitions to file: %v", err)
	}

	// Fetch CVSS scores for CVEs from NVD
	if err := fetchCVSSFromNVDForAll(cveData); err != nil {
		log.Fatalf("Error fetching CVSS scores from NVD: %v", err)
	}

	fmt.Println("GLSA-OVAL generation completed successfully.")
}
