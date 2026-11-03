package main

import (
	"database/sql"
	"fmt"
)

func lookup(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = ?", name)
}

func main() {
	fmt.Println("ok")
}
