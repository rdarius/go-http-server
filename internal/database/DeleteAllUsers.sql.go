// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: DeleteAllUsers.sql

package database

import (
	"context"
)

const deleteAllUser = `-- name: DeleteAllUser :exec
DELETE FROM users WHERE true
`

func (q *Queries) DeleteAllUser(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllUser)
	return err
}
