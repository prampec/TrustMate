CREATE TABLE certificates (
    serial            TEXT PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('root','intermediate','leaf')),
    profile_name      TEXT NOT NULL DEFAULT '',
    subject           TEXT NOT NULL,
    issuer_serial     TEXT REFERENCES certificates(serial),
    not_before        TIMESTAMPTZ NOT NULL,
    not_after         TIMESTAMPTZ NOT NULL,
    pem               BYTEA NOT NULL,
    key_ref           TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ,
    revocation_reason TEXT NOT NULL DEFAULT '',
    seq               BIGINT GENERATED ALWAYS AS IDENTITY
);
CREATE INDEX idx_certificates_kind ON certificates(kind);
CREATE INDEX idx_certificates_profile_name ON certificates(profile_name);

CREATE TABLE profiles (
    name       TEXT NOT NULL,
    version    INTEGER NOT NULL,
    data       BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (name, version)
);

CREATE TABLE audit_log (
    id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts     TIMESTAMPTZ NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);

CREATE TABLE client_roles (
    cert_serial TEXT PRIMARY KEY REFERENCES certificates(serial),
    role        TEXT NOT NULL CHECK (role IN ('admin','manager')),
    created_at  TIMESTAMPTZ NOT NULL
);
