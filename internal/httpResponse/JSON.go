package httpResponse

import (
	"log"
	"net/http"
)

func JSONHandler(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, err := w.Write([]byte(text))
	if err != nil {
		log.Default().Println(err)
	}
}
