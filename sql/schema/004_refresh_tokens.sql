-- +goose Up
CREATE TABLE refresh_tokens(
    token TEXT PRIMARY KEY,
    created_at TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP,
    user_id UUID not null REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamp not null,
    revoked_at timestamp default null
);

-- +goose Down
DROP TABLE refresh_tokens;