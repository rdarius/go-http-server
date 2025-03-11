-- name: DeleteChirpByID :exec
DELETE FROM chirps WHERE id = $1;