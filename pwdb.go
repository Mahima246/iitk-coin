package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3" // Import go-sqlite3 library
)

type User struct{
	name   string
	rollno string
}

func main() {
	os.Remove("sqlite-database.db")//removing the pre-exiting db file

	file, err := os.Create("sqlite-database.db") // Creating SQLite database file
	if err != nil {
		log.Fatal(err.Error())
	}
	file.Close()

	sqliteDatabase, _ := sql.Open("sqlite3", "./sqlite-database.db") // Open the created SQLite File
	defer sqliteDatabase.Close()                                     // Defer Closing the database
	createTable(sqliteDatabase)                                      // Create Database Tables

	// Inserting RECORDS

	s := User{name: "Mahima", rollno: "190469"}
	insertUser(sqliteDatabase, &s)

	// Displaying INSERTED RECORDS
	displayUsers(sqliteDatabase)
}

func createTable(db *sql.DB) {
	createUserTableSQL := `CREATE TABLE User (
		"User" integer NOT NULL PRIMARY KEY AUTOINCREMENT,		
		"name" TEXT,
		"rollno" TEXT		
	  );`
	statement, err := db.Prepare(createUserTableSQL)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()
}

// Passing db reference connection from main to our method with struct parameter
func insertUser(db *sql.DB, u *User) {

	// name := u.name
	// rollno := u.rollno
	insertUserSQL := `INSERT INTO User( name, rollno) VALUES (?, ?)`
	statement, err := db.Prepare(insertUserSQL) 

	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(u.name, u.rollno)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func displayUsers(db *sql.DB) {
	row, err := db.Query("SELECT * FROM User ORDER BY name")
	if err != nil {
		log.Fatal(err)
	}
	defer row.Close()
	//Iterating and fetching all the records from User table
	for row.Next() { 
		var id int
		var name string
		var rollno string
		row.Scan(&id, &name, &rollno)
		fmt.Println("User: ", name, " ", rollno)
	}
}
