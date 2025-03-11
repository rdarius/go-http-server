-- +goose Up
CREATE TABLE chirps(
    id UUID PRIMARY KEY,
    created_at TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP,
    body TEXT not null UNIQUE,
    user_id UUID not null REFERENCES users(id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE chirps;