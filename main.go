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

	// Parse GLSA page and store OVAL definitions in a buffer
	definitions, err := parseGLSA(pageContent)
	if err != nil {
		log.Fatalf("Error parsing GLSA page: %v", err)
	}

	// Store OVAL definitions
	storeOVALDefinitions(definitions)

	// Additional logic can be added here if needed
}
