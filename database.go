package main

import (
	"database/sql"
	"encoding/json"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/quay/goval-parser/oval"
)

func initializeDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./GLSA-oval.db")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS definitions (
			id TEXT PRIMARY KEY,
			title TEXT,
			description TEXT,
			references TEXT
		);
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func saveDefinitions(db *sql.DB, definitions *oval.Definitions) error {
	for _, def := range definitions.Definitions {
		references, err := json.Marshal(def.Advisory.Refs)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			INSERT OR REPLACE INTO definitions (id, title, description, references)
			VALUES (?, ?, ?, ?)
		`, def.ID, def.Title, def.Description, string(references))
		if err != nil {
			return err
		}
	}
	return nil
}
