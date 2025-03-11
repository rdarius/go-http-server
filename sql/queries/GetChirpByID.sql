-- name: GetChirpByID :one
SELECT * FROM chirps WHERE id = $1;