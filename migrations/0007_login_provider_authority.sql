-- V1-04 operator-owned login provider authority (ADR 0012). The API only reads it.
-- Owner write protocol: one bounded transaction locks the stable login_providers row
-- FOR UPDATE before inserting the next revision row, and holds that lock until commit.
-- Identity values are allocation order, not commit order; the row lock serializes writers.
CREATE TABLE openmettle.login_providers (
    id uuid PRIMARY KEY,
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 255),
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Append-only by protocol. The latest epoch per provider is current; NULL revision retires.
CREATE TABLE openmettle.login_provider_revisions (
    epoch bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider_id uuid NOT NULL REFERENCES openmettle.login_providers (id),
    revision text CHECK (revision ~ '^[A-Za-z0-9_-]{1,64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_provider_revisions_current_idx
    ON openmettle.login_provider_revisions (provider_id, epoch DESC);
GRANT SELECT ON openmettle.login_providers, openmettle.login_provider_revisions
    TO openmettle_api;
