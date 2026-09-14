CREATE TABLE acme_eab_tokens (
    key_id     TEXT PRIMARY KEY,
    hmac_key   BLOB NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('admin','manager')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE acme_accounts (
    id             TEXT PRIMARY KEY,
    jwk_thumbprint TEXT NOT NULL UNIQUE,
    public_key_jwk BLOB NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('admin','manager')),
    eab_key_id     TEXT NOT NULL REFERENCES acme_eab_tokens(key_id),
    created_at     TEXT NOT NULL
);

CREATE TABLE acme_orders (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES acme_accounts(id),
    identifier  TEXT NOT NULL,
    status      TEXT NOT NULL,
    cert_serial TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE acme_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
);
