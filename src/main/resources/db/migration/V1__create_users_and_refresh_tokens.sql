-- SplitExpense auth-service: initial schema.
-- Owns users, their credentials, and the refresh tokens issued to them.

CREATE TABLE users (
    id            UUID         NOT NULL,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(150) NOT NULL,
    phone_number  VARCHAR(20),
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    role          VARCHAR(20)  NOT NULL DEFAULT 'USER',
    created_at    TIMESTAMPTZ  NOT NULL,
    updated_at    TIMESTAMPTZ  NOT NULL,

    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_email UNIQUE (email),
    -- Enforced here too, so writes from any other client are rejected.
    CONSTRAINT ck_users_role CHECK (role IN ('USER', 'ADMIN'))
);

-- Named explicitly, though uq_users_email already indexes this column.
CREATE INDEX idx_users_email ON users (email);

CREATE TABLE refresh_tokens (
    id          UUID         NOT NULL,
    token       VARCHAR(512) NOT NULL,
    user_id     UUID         NOT NULL,
    expiry_date TIMESTAMPTZ  NOT NULL,
    revoked     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL,

    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uq_refresh_tokens_token UNIQUE (token),
    -- Deleting a user must not strand their tokens.
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

-- Supports "revoke every token for this user" (logout-everywhere, password change).
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- Supports cleaning up expired tokens without a full table scan.
CREATE INDEX idx_refresh_tokens_expiry_date ON refresh_tokens (expiry_date);
