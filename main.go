package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rdarius/go-http-server/internal/database"
	"github.com/rdarius/go-http-server/internal/httpResponse"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             database.Queries
	platform       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	httpResponse.PlainTextHandler(w, http.StatusOK, "OK")
}

func metricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits := cfg.fileserverHits.Load()
		httpResponse.PlainTextHandler(w, http.StatusOK, fmt.Sprintf("Hits: %d", hits))
	}
}

func adminMetricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits := cfg.fileserverHits.Load()
		httpResponse.HTMLHandler(w, http.StatusOK, fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits))
	}
}
func resetMetricsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if cfg.platform != "dev" {
			httpResponse.JSONHandler(w, http.StatusForbidden, `{"error": "Forbidden!"}`)
			return
		}

		err := cfg.db.DeleteAllUser(context.Background())
		if err != nil {
			httpResponse.SomethingWentWrong(w)
			return
		}
		cfg.fileserverHits.Store(0)
		httpResponse.PlainTextHandler(w, http.StatusOK, "Metrics Reset")
	}
}

func fileServerHandler() http.Handler {
	fileServer := http.FileServer(http.Dir("./public"))
	return http.StripPrefix("/app", fileServer)
}

func postUsersHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
		}

		params := parameters{}
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, `{"error": "Failed to parse request body"}`)
			return
		}

		usr, err := cfg.db.CreateUser(context.Background(), params.Email)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusInternalServerError, fmt.Sprintf(`{"error": "Failed to create user", "message": "%s"}`, err.Error()))
			return
		}

		jsonData := fmt.Sprintf(`{
			"id": "%s",
			"created_at": "%s",
			"updated_at": "%s",
			"email": "%s"
			}`, usr.ID, usr.CreatedAt, usr.UpdatedAt, usr.Email)
		httpResponse.JSONHandler(w, http.StatusCreated, jsonData)
	}
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
		httpResponse.SomethingWentWrong(w)
		return
	}

	if len(params.Body) > 140 {
		httpResponse.JSONHandler(w, http.StatusBadRequest, `{"error": "Chirp is too long"}`)
		return
	}

	chirp := params.Body

	for _, word := range profaneWords {
		// Use word boundaries (\b) to match whole words and ignore punctuation
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
		chirp = re.ReplaceAllString(chirp, "****")
	}

	httpResponse.JSONHandler(w, http.StatusOK, fmt.Sprintf(`{"cleaned_body": "%s"}`, chirp))
	return
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	apiCfg := &apiConfig{}

	dbURL := os.Getenv("DB_URL")

	apiCfg.platform = os.Getenv("PLATFORM")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	dbQueries := database.New(db)
	apiCfg.db = *dbQueries

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /api/metrics", metricsHandler(apiCfg))
	mux.HandleFunc("POST /api/reset", resetMetricsHandler(apiCfg))
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	mux.HandleFunc("POST /api/users", postUsersHandler(apiCfg))

	mux.HandleFunc("GET /admin/metrics", adminMetricsHandler(apiCfg))
	mux.HandleFunc("POST /admin/reset", resetMetricsHandler(apiCfg))

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
