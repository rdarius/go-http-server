// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: GetChirpByID.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const getChirpByID = `-- name: GetChirpByID :one
SELECT id, created_at, updated_at, body, user_id FROM chirps WHERE id = $1
`

func (q *Queries) GetChirpByID(ctx context.Context, id uuid.UUID) (Chirp, error) {
	row := q.db.QueryRowContext(ctx, getChirpByID, id)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Body,
		&i.UserID,
	)
	return i, err
}
