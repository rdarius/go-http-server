package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rdarius/go-http-server/internal/auth"
	"github.com/rdarius/go-http-server/internal/dataMaps"
	"github.com/rdarius/go-http-server/internal/database"
	"github.com/rdarius/go-http-server/internal/httpResponse"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             database.Queries
	platform       string
	secret         string
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

func getAllChirpsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		chirps, err := cfg.db.GetAllChirps(context.Background())
		if err != nil {
			httpResponse.SomethingWentWrong(w)
		}

		data := make([]dataMaps.Chirp, 0)
		for _, chirp := range chirps {
			data = append(data, dataMaps.Chirp{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
			})
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			httpResponse.SomethingWentWrong(w)
		}
		httpResponse.PlainTextHandler(w, http.StatusOK, string(jsonData))
	}
}

func getChirpByIDHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		chirpID, err := uuid.Parse(r.PathValue("chirpID"))
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, `{"error": "InvalidChirpID"}`)
		}

		chirp, err := cfg.db.GetChirpByID(context.Background(), chirpID)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusNotFound, `{"error": "ChirpNotFound"}`)
		}

		data := dataMaps.Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			httpResponse.SomethingWentWrong(w)
		}
		httpResponse.PlainTextHandler(w, http.StatusOK, string(jsonData))
	}
}

func postChirpsHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Body string `json:"body"`
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusUnauthorized, `{"error": "Unauthorized"}`)
		}

		uuid, err := auth.ValidateJWT(token, cfg.secret)

		params := parameters{}
		err = json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, `{"error": "Failed to parse request body"}`)
			return
		}

		chirp, err := validateChirp(params.Body)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			return
		}

		newChirp, err := cfg.db.CreateChirp(context.Background(), database.CreateChirpParams{
			Body:   chirp,
			UserID: uuid,
		})
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusInternalServerError, fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			return
		}

		chirpJSON := dataMaps.Chirp{
			ID:        newChirp.ID,
			CreatedAt: newChirp.CreatedAt,
			UpdatedAt: newChirp.UpdatedAt,
			Body:      newChirp.Body,
			UserID:    newChirp.UserID,
		}

		jsonData, err := json.Marshal(chirpJSON)
		if err != nil {
			httpResponse.SomethingWentWrong(w)
			return
		}
		httpResponse.JSONHandler(w, http.StatusCreated, string(jsonData))
	}
}
func loginHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email            string `json:"email"`
			Password         string `json:"password"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
		}

		params := parameters{}
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, `{"error": "Failed to parse request body"}`)
			return
		}

		user, err := cfg.db.GetUserByEmail(context.Background(), params.Email)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusNotFound, `{"error": "UserNotFound"}`)
			return
		}

		err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusUnauthorized, `{"error": "Incorrect email or password"}`)
			return
		}

		if params.ExpiresInSeconds == 0 || params.ExpiresInSeconds > 3600 {
			params.ExpiresInSeconds = 3600
		}

		userJSON := dataMaps.UserWithToken{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}

		expiresIn := time.Duration(params.ExpiresInSeconds) * time.Second

		userJSON.Token, err = auth.MakeJWT(user.ID, cfg.secret, expiresIn)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			return
		}

		jsonData, err := json.Marshal(userJSON)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusInternalServerError, fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			return
		}
		httpResponse.JSONHandler(w, http.StatusOK, string(jsonData))
	}
}

func postUsersHandler(cfg *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		params := parameters{}
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusBadRequest, `{"error": "Failed to parse request body"}`)
			return
		}

		hash, err := auth.HashPassword(params.Password)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusInternalServerError, fmt.Sprintf(`{"error": "%s"}`, err.Error()))
		}

		usr, err := cfg.db.CreateUser(context.Background(), database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hash,
		})

		if err != nil {
			httpResponse.JSONHandler(w, http.StatusInternalServerError, fmt.Sprintf(`{"error": "Failed to create user", "message": "%s"}`, err.Error()))
			return
		}

		userJSON := dataMaps.User{
			ID:        usr.ID,
			CreatedAt: usr.CreatedAt,
			UpdatedAt: usr.UpdatedAt,
			Email:     usr.Email,
		}

		jsonData, err := json.Marshal(userJSON)
		if err != nil {
			httpResponse.JSONHandler(w, http.StatusInternalServerError, fmt.Sprintf(`{"error": "%s"}`, err.Error()))
		}
		httpResponse.JSONHandler(w, http.StatusCreated, string(jsonData))
	}
}

func validateChirp(chirp string) (string, error) {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	if len(chirp) > 140 {
		return "", fmt.Errorf("chirp is too long")
	}

	for _, word := range profaneWords {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
		chirp = re.ReplaceAllString(chirp, "****")
	}

	return chirp, nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	apiCfg := &apiConfig{}

	dbURL := os.Getenv("DB_URL")

	apiCfg.platform = os.Getenv("PLATFORM")
	apiCfg.secret = os.Getenv("SECRET")

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
	mux.HandleFunc("POST /api/users", postUsersHandler(apiCfg))
	mux.HandleFunc("POST /api/login", loginHandler(apiCfg))
	mux.HandleFunc("POST /api/chirps", postChirpsHandler(apiCfg))
	mux.HandleFunc("GET /api/chirps", getAllChirpsHandler(apiCfg))
	mux.HandleFunc("GET /api/chirps/{chirpID}", getChirpByIDHandler(apiCfg))

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
