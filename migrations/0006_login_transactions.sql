-- Internal browser transactions only. No admission, accounts or application sessions.
-- Reservations commit separately before encryption and survive all later failures.
CREATE TABLE openmettle.login_nonce_reservations (
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    PRIMARY KEY (key_id, nonce)
);
CREATE TABLE openmettle.login_transactions (
    id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
    binding bytea NOT NULL CHECK (octet_length(binding) BETWEEN 1 AND 12288),
    expires_ms bigint NOT NULL CHECK (expires_ms > 0),
    state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    caller_hash bytea NOT NULL CHECK (octet_length(caller_hash) = 32),
    key_id text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea,
    consumed boolean NOT NULL DEFAULT false,
    FOREIGN KEY (key_id, nonce) REFERENCES openmettle.login_nonce_reservations (key_id, nonce),
    UNIQUE (key_id, nonce),
    CHECK ((consumed AND ciphertext IS NULL) OR
        (NOT consumed AND ciphertext IS NOT NULL AND octet_length(ciphertext) = 59))
);
GRANT SELECT ON openmettle.login_nonce_reservations, openmettle.login_transactions TO openmettle_api;
GRANT INSERT (key_id, nonce) ON openmettle.login_nonce_reservations TO openmettle_api;
GRANT INSERT (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext)
    ON openmettle.login_transactions TO openmettle_api;
GRANT UPDATE (consumed,ciphertext) ON openmettle.login_transactions TO openmettle_api;
