package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/aligorov/twofa/internal/api"
)

func main() {
	dsnFlag := flag.String("dsn", "", "PostgreSQL DSN (приоритет над env TWOFA_DB_DSN)")
	flag.Parse()

	dsn := *dsnFlag
	if dsn == "" {
		dsn = os.Getenv("TWOFA_DB_DSN")
	}
	// Подключение к БД появится в последующих задачах; DSN пока только парсится.
	_ = dsn

	const addr = ":8080"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, api.NewRouter()); err != nil {
		log.Fatal(err)
	}
}
