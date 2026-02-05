package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	// Serve static files from /static (we'll copy project files there in the image)
	fs := http.FileServer(http.Dir("/static"))
	mux.Handle("/", fs)

	srv := &http.Server{
		Addr:         ":80",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Println("Starting static server on :80")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
