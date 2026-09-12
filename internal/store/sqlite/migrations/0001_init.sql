CREATE TABLE certificates (
    serial        TEXT PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('root','intermediate','leaf')),
    profile_name  TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL,
    issuer_serial TEXT REFERENCES certificates(serial),
    not_before    TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    pem           BLOB NOT NULL,
    key_ref       TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_certificates_kind ON certificates(kind);
CREATE INDEX idx_certificates_profile_name ON certificates(profile_name);

CREATE TABLE profiles (
    name       TEXT NOT NULL,
    version    INTEGER NOT NULL,
    data       BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name, version)
);

CREATE TABLE audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT,
    detail  TEXT
);
