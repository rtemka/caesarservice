package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"cypherservice/pkg/api/restapi"
)

func main() {

	logger := log.New(os.Stdout, "[WEB API] ", log.Lmsgprefix|log.LstdFlags)

	api := restapi.New(logger)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           api.Router(),
		IdleTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
	}

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
