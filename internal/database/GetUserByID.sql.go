// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: GetUserByID.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const getUserByID = `-- name: GetUserByID :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users WHERE id = $1
`

func (q *Queries) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}
