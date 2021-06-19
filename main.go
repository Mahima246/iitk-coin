package main
import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
	"strconv"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3" // Import go-sqlite3 library
	"golang.org/x/crypto/bcrypt"
)
type User struct {
	Name string `json:"Name"`
	Coins int `json:"Coins"`
	Rollno     string `json:"Rollno"`
	Passwd     string `json:"Passwd"`
	Batch      string `json:"Batch"`
	IsAdmin    bool   `json:"IsAdmin"`
	EventsPart string `json:"EventsPart"`
	Iscordi    bool   `json:"IsCordi"`
}

type auth struct {
	Rollno string `json:"Rollno"`
	Passwd string `json:"Passwd"`
}

type coinrew struct{
	Rollno string `json:"Rollno"`
	Coins int `json:"Coins"`
}
type cointrans struct{
	Rollno1 string `json:"Rollno1"`
	Rollno2 string `json:"Rollno2"`
	Coins int `json:"Coins"`
}

type vw struct{
	Rollno string `json:"Rollno"`
}

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Rollno string `json:"Rollno"`
	jwt.StandardClaims
}


func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}







func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var outh auth
	body, _ := ioutil.ReadAll(r.Body)
	rerr := json.Unmarshal(body, &outh)
	log.Println(rerr)
	if rerr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var pswd string
	db, _ := sql.Open("sqlite3", "./sqlite-database.db")
	res := db.QueryRow("SELECT passwd FROM auth WHERE Rollno = ?", outh.Rollno).Scan(&pswd)
	
	if res == sql.ErrNoRows {
		http.Error(w, "No User found!", http.StatusNotFound)
		return
	}
	
	if res != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(res)
	}
	err := bcrypt.CompareHashAndPassword([]byte(pswd), []byte(outh.Passwd))
	if err != nil {
		http.Error(w, "Invalid Password", http.StatusUnauthorized)
		return
	}
	log.Println("User Logged in")
	expirationTime := time.Now().Add(15 * time.Minute)
	// Create the JWT claims, which includes the rollnp and expiry time
	
	claims := &Claims{
		Rollno: outh.Rollno,

		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		http.Error(w, "Error while generating token,Try again", http.StatusInternalServerError)
		log.Println(err)
		json.NewEncoder(w).Encode(res)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}






func signupHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var user User
	// err := json.NewDecoder(r.Body).Decode(&user)
	// log.Println(err)
	// if err != nil {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }
	// =================================OR===================================
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}

	var outh auth
	outh.Rollno = user.Rollno
	hpwd, _ := HashPassword(user.Passwd)
	outh.Passwd = hpwd[:]
	user.Passwd = hpwd[:]
	log.Println(user.Rollno)
	log.Println(user.Passwd)

	sqliteDatabase, _ := sql.Open("sqlite3", "./sqlite-database.db")
	insertUser(sqliteDatabase, &user)
	insertauth(sqliteDatabase, &outh)
}






func secretpageHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "You are Unauthorized! ", http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		http.Error(w, "Bad Request ", http.StatusBadRequest)
		return
	}
	// Get the JWT string from the cookie
	tknStr := c.Value
	// Initialize a new instance of `Claims`
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "You are Unauthorized! ", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Bad Request ", http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		http.Error(w, "You are Unauthorized! ", http.StatusUnauthorized)
		return
	}
	w.Write([]byte(fmt.Sprintf("Welcome to IITK coins %s!", claims.Rollno)))
}






func view(w http.ResponseWriter, r *http.Request){
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var vw vw
	body, _ := ioutil.ReadAll(r.Body)
	rerr := json.Unmarshal(body, &vw)
	log.Println(rerr)
	if rerr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var rollno = vw.Rollno
	var coin int
	db, _ := sql.Open("sqlite3", "./sqlite-database.db")
	res := db.QueryRow("SELECT Coins FROM User WHERE Rollno = ?", rollno).Scan(&coin)
	
	if res == sql.ErrNoRows {
		http.Error(w, "No User found!", http.StatusNotFound)
		return
	}
	
	if res != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(res)
	}
	s := strconv.Itoa(coin)
	log.Println(s)

	w.Write([]byte(fmt.Sprintf("Coins in your wallet: %s!", s)))
}







func reward(w http.ResponseWriter, r *http.Request){
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var coin coinrew	
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &coin)
	if err != nil {
		log.Fatal(err)
	}

	var coins int
	db, _ := sql.Open("sqlite3", "./sqlite-database.db")
	res := db.QueryRow("SELECT Coins FROM User WHERE Rollno = ?", coin.Rollno).Scan(&coins)
	
	if res == sql.ErrNoRows {
		http.Error(w, "No User found!", http.StatusNotFound)
		return
	}
	
	if res != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(res)
	}

	coins = coins + coin.Coins

	log.Println(coins)
	statement, err := db.Prepare("UPDATE User SET Coins = ? WHERE Rollno = ?")
	
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(coins,coin.Rollno)
	if err != nil {
		log.Fatalln(err.Error())
	}
}







func transfer(w http.ResponseWriter, r *http.Request){
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var cointr cointrans	
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &cointr)
	if err != nil {
		log.Fatal(err)
	}

	var coins1 int
	var coins2 int
	db, _ := sql.Open("sqlite3", "./sqlite-database.db")
	res := db.QueryRow("SELECT Coins FROM User WHERE Rollno = ?", cointr.Rollno1).Scan(&coins1)
	res2 := db.QueryRow("SELECT Coins FROM User WHERE Rollno = ?", cointr.Rollno2).Scan(&coins2)
	
	if res == sql.ErrNoRows {
		http.Error(w, "1st User Not found!", http.StatusNotFound)
		return
	}
	
	if res != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(res)
	}
	if res2 == sql.ErrNoRows {
		http.Error(w, "1st User Not found!", http.StatusNotFound)
		return
	}
	
	if res2 != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(res2)
	}

	if coins1<cointr.Coins{
		http.Error(w, "uhoh, User 1 doesn't have enough coins to transfer to user 2", http.StatusBadRequest)
		log.Fatalln("User 1 doesn't have enough coins to transfer to user 2")
	}
	statement1, err1 := db.Prepare("UPDATE User SET Coins = ? WHERE Rollno = ?")
	
	if err1 != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Fatalln(err1.Error())
	}
	_, err1 = statement1.Exec(coins1-cointr.Coins,cointr.Rollno1)
	if err1 != nil {
		log.Fatalln(err1.Error())
	}

	statement, err := db.Prepare("UPDATE User SET Coins = ? WHERE Rollno = ?")
	
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(coins2+cointr.Coins,cointr.Rollno2)
	if err != nil {
		log.Fatalln(err.Error())
	}
}







func main() {
	r := mux.NewRouter()
	r.HandleFunc("/signup", signupHandler).
		Methods("POST")
	r.HandleFunc("/login", loginHandler).
		Methods("POST")
	r.HandleFunc("/secretpage", secretpageHandler).
		Methods("GET")
	r.HandleFunc("/reward",reward).
		Methods("POST")
	r.HandleFunc("/view",view).
		Methods("GET")
	r.HandleFunc("/transfer",transfer).
		Methods("POST")
	
	file, err := os.Create("sqlite-database.db") // Creating SQLite database file
	if err != nil {
		log.Fatal(err.Error())
	}
	file.Close()
	sqliteDatabase, _ := sql.Open("sqlite3", "./sqlite-database.db") // Open the created SQLite File
	defer sqliteDatabase.Close()                                     // Defer Closing the database
	createTable(sqliteDatabase)                                      // Create Database Tables

	fmt.Printf("Starting server at port 8080\n")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func createTable(db *sql.DB) {
	createUserTableSQL := `CREATE TABLE User (
		User INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,		
		Name TEXT,
		Passwd TEXT,
		Rollno TEXT,
		Coins INTEGER,
		Batch TEXT,
		EventsPart TEXT,
		IsAdmin INTEGER,
		IsCordi INTEGER
		)`
	statement, err := db.Prepare(createUserTableSQL)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()

	createauthTableSQL := `CREATE TABLE auth (	
		Rollno TEXT,
		Passwd TEXT		
	)`
	st, err := db.Prepare(createauthTableSQL)
	if err != nil {
		log.Fatal(err.Error())
	}
	st.Exec()
}


func insertUser(db *sql.DB, u *User) {

	insertUserSQL := `INSERT INTO User( Name, Passwd ,Rollno, Coins, Batch, EventsPart, IsAdmin, IsCordi) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	statement, err := db.Prepare(insertUserSQL)
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(u.Name, u.Passwd, u.Rollno, u.Coins, u.Batch, u.EventsPart, u.IsAdmin, u.Iscordi)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func insertauth(db *sql.DB, u *auth) {
	insertauthSQL := `INSERT INTO auth( rollno, passwd) VALUES (?, ?)`
	statement, err := db.Prepare(insertauthSQL)
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(u.Rollno, u.Passwd)
	if err != nil {
		log.Fatalln(err.Error())
	}
}
