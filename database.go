package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/quay/goval-parser/oval"
)

// storeOVALDefinitionsInDB stores OVAL definitions in a SQLite database
func storeOVALDefinitionsInDB(definitions *oval.Definitions) error {
	// Open or create an SQLite database file
	db, err := sql.Open("sqlite3", "oval_GLSA.db")
	if err != nil {
		return fmt.Errorf("error opening SQLite database: %v", err)
	}
	defer db.Close()

	// Create a table to store OVAL definitions (if it doesn't exist)
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS oval_definitions (
            id TEXT PRIMARY KEY,
            definition TEXT NOT NULL
        )
    `)
	if err != nil {
		return fmt.Errorf("error creating table: %v", err)
	}

	// Insert OVAL definitions into the SQLite table
	for _, definition := range definitions.Definitions {
		definitionXML, err := definition.MarshalXML()
		if err != nil {
			return fmt.Errorf("error serializing OVAL definition: %v", err)
		}

		_, err = db.Exec("INSERT INTO oval_definitions (id, definition) VALUES (?, ?)", definition.ID, string(definitionXML))
		if err != nil {
			return fmt.Errorf("error inserting OVAL definition: %v", err)
		}
	}

	fmt.Println("OVAL definitions stored in SQLite database")
	return nil
}
