CREATE TABLE IF NOT EXISTS all_ips (
    ip            TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    generation    INTEGER,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    sources       TEXT    NOT NULL DEFAULT '',
    title         TEXT,
    country       TEXT,
    asn           TEXT,
    org           TEXT,
    is_alive      INTEGER NOT NULL DEFAULT 1,
    firmware      TEXT,
    notes         TEXT,
    PRIMARY KEY (ip, port)
);

CREATE INDEX IF NOT EXISTS idx_all_last   ON all_ips(last_seen);
CREATE INDEX IF NOT EXISTS idx_all_gen    ON all_ips(generation);
CREATE INDEX IF NOT EXISTS idx_all_alive  ON all_ips(is_alive);

CREATE TABLE IF NOT EXISTS vuln_ips (
    ip                 TEXT    NOT NULL,
    port               INTEGER NOT NULL,
    generation         INTEGER,
    first_seen         TEXT    NOT NULL,
    last_seen          TEXT    NOT NULL,
    vuln_confirmed_at  TEXT    NOT NULL,
    sources            TEXT    NOT NULL DEFAULT '',
    title              TEXT,
    country            TEXT,
    asn                TEXT,
    org                TEXT,
    firmware           TEXT,
    confidence         INTEGER NOT NULL DEFAULT 0,
    proof              TEXT,
    PRIMARY KEY (ip, port)
);

CREATE INDEX IF NOT EXISTS idx_vuln_conf ON vuln_ips(vuln_confirmed_at);

CREATE TABLE IF NOT EXISTS api_keys (
    engine     TEXT NOT NULL,
    slot       INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    added_at   TEXT NOT NULL,
    PRIMARY KEY (engine, slot)
);

CREATE TABLE IF NOT EXISTS counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
