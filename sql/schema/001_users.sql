-- +goose Up
CREATE TABLE users(
    id UUID PRIMARY KEY,
    created_at TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP,
    email TEXT not null
);

-- +goose Down
DROP TABLE users;