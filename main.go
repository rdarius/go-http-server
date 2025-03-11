package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func metricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		hits := cfg.fileserverHits.Load()
		w.Write([]byte(fmt.Sprintf("Hits: %d", hits)))
	}
}

func adminMetricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		hits := cfg.fileserverHits.Load()
		w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)))
	}
}
func resetMetricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		cfg.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Metrics Reset"))
	}
}
func adminResetMetricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		cfg.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Metrics Reset"))
	}
}

func fileServerHandler() http.Handler {
	fileServer := http.FileServer(http.Dir("./public"))
	return http.StripPrefix("/app", fileServer)
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Something went wrong"}`))
		return
	}

	if len(params.Body) > 140 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Chirp is too long"}`))
		return
	}

	chirp := params.Body

	for _, word := range profaneWords {
		// Use word boundaries (\b) to match whole words and ignore punctuation
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
		chirp = re.ReplaceAllString(chirp, "****")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"cleaned_body": "%s"}`, chirp)))
	return
}

func main() {

	apiCfg := &apiConfig{}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /api/metrics", metricsHandler(apiCfg))
	mux.HandleFunc("POST /api/reset", resetMetricsHandler(apiCfg))
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	mux.HandleFunc("GET /admin/metrics", adminMetricsHandler(apiCfg))
	mux.HandleFunc("POST /admin/reset", adminResetMetricsHandler(apiCfg))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServerHandler()))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
