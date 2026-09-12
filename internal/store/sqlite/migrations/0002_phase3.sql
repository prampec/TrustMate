ALTER TABLE certificates ADD COLUMN revoked_at TEXT;
ALTER TABLE certificates ADD COLUMN revocation_reason TEXT NOT NULL DEFAULT '';

CREATE TABLE client_roles (
    cert_serial TEXT PRIMARY KEY REFERENCES certificates(serial),
    role        TEXT NOT NULL CHECK (role IN ('admin','manager')),
    created_at  TEXT NOT NULL
);
