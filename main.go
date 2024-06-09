package main

import (
	"log"
)

func main() {
	// Initialize the database
	db, err := initializeDatabase()
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	defer db.Close()

	// Fetch GLSA page
	pageContent, err := fetchPage("https://security.gentoo.org/")
	if err != nil {
		log.Fatalf("Error fetching GLSA page: %v", err)
	}

	// Parse GLSA page
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(pageContent))
	if err != nil {
		log.Fatalf("Error parsing GLSA page: %v", err)
	}

	// Generate OVAL definitions
	definitions, err := generateOVALDefinitions(doc)
	if err != nil {
		log.Fatalf("Error generating OVAL definitions: %v", err)
	}

	// Save definitions to the database
	if err := saveDefinitions(db, definitions); err != nil {
		log.Fatalf("Error saving definitions to database: %v", err)
	}

	// Write definitions to an XML file
	if err := writeOVALDefinitionsToFile(definitions, "GLSA-oval.xml"); err != nil {
		log.Fatalf("Error writing OVAL definitions to file: %v", err)
	}
}
