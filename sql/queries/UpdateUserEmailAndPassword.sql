-- name: UpdateUserEmailAndPassword :one
UPDATE users SET email = $1, hashed_password = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3
RETURNING *;