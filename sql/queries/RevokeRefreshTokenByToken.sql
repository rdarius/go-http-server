-- name: RevokeRefreshTokenByToken :exec
UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token = $1;