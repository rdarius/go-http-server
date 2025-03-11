package httpResponse

import (
	"net/http"
)

func SomethingWentWrong(w http.ResponseWriter) {
	JSONHandler(w, http.StatusInternalServerError, `{"error": "Something went wrong"}`)
}
