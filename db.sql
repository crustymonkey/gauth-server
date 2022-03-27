CREATE TABLE IF NOT EXISTS loc_auth (
    id BIGSERIAL PRIMARY KEY,
    host VARCHAR(1024),
    api_key VARCHAR(256)
);

CREATE INDEX IF NOT EXISTS host_idx ON loc_auth (host);
CREATE UNIQUE INDEX IF NOT EXISTS api_key_idx ON loc_auth (api_key);

CREATE TABLE IF NOT EXISTS secrets (
    id BIGSERIAL PRIMARY KEY,
    ident VARCHAR(4096),  -- This is an arbitrary string identifier
    token VARCHAR(128)  -- This is the actual secret token
);

CREATE UNIQUE INDEX IF NOT EXISTS ident_idx ON secrets (ident);
CREATE UNIQUE INDEX IF NOT EXISTS token_idx ON secrets (token);