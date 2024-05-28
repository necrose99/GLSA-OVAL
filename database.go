package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// initializeDatabase initializes the SQLite database
func initializeDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "oval_GLSA.db")
	if err != nil {
		return nil, err
	}

	// Create tables if they do not exist
	query := `
	CREATE TABLE IF NOT EXISTS definitions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT,
		description TEXT
	);
	CREATE TABLE IF NOT EXISTS references (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		definition_id INTEGER,
		ref_id TEXT,
		FOREIGN KEY(definition_id) REFERENCES definitions(id)
	);
	`

	if _, err := db.Exec(query); err != nil {
		return nil, err
	}

	return db, nil
}

// saveDefinition saves a single OVAL definition to the database
func saveDefinition(db *sql.DB, definition *oval.Definition) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	result, err := tx.Exec("INSERT INTO definitions (title, description) VALUES (?, ?)", definition.Title, definition.Description)
	if err != nil {
		tx.Rollback()
		return err
	}

	definitionID, err := result.LastInsertId()
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, ref := range definition.References {
		if _, err := tx.Exec("INSERT INTO references (definition_id, ref_id) VALUES (?, ?)", definitionID, ref.RefID); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// saveDefinitions saves multiple OVAL definitions to the database
func saveDefinitions(db *sql.DB, definitions *oval.Definitions) error {
	for _, definition := range definitions.Definitions {
		if err := saveDefinition(db, definition); err != nil {
			return err
		}
	}
	return nil
}
