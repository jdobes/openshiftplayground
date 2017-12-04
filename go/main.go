package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/plain")
	fmt.Fprint(w, "Hello world!\n\n")
}

func one(w http.ResponseWriter, r *http.Request) {
        h := w.Header()
        h.Set("Content-Type", "text/plain")
        fmt.Fprint(w, "[one]")
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/one", one)
	http.ListenAndServe(":80", nil)
}
