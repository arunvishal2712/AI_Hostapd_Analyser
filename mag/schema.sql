CREATE TABLE IF NOT EXISTS tests (
    test_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    ap_name TEXT,
    ssid TEXT,
    security TEXT,
    channel INTEGER,
    client_count INTEGER,
    authentication_failures INTEGER,
    association_failures INTEGER,
    handshake_failures INTEGER,
    deauthentication_events INTEGER,
    disassociation_events INTEGER,
    reconnections INTEGER,
    raw_statistics_json TEXT,
    parser_version TEXT,
    log_format TEXT,
    log_start TEXT,
    log_end TEXT,
    driver_errors INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clients (
    client_mac TEXT PRIMARY KEY,
    first_seen_test TEXT,
    first_seen_at TEXT,
    last_seen_test TEXT,
    last_seen_at TEXT,
    total_tests INTEGER DEFAULT 0,
    total_failures INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS test_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES tests(test_id),
    client_mac TEXT NOT NULL REFERENCES clients(client_mac),
    authentication TEXT,
    association TEXT,
    handshake TEXT,
    deauth_count INTEGER DEFAULT 0,
    disassoc_count INTEGER DEFAULT 0,
    reconnect_count INTEGER DEFAULT 0,
    issues_json TEXT,
    failure_count INTEGER DEFAULT 0,
    failure_score INTEGER DEFAULT 0,
    reason_codes_json TEXT,
    UNIQUE(test_id, client_mac)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES tests(test_id),
    client_mac TEXT,
    timestamp TEXT,
    event_type TEXT NOT NULL,
    reason_code INTEGER,
    message TEXT,
    subtype TEXT,
    initiator TEXT,
    interface TEXT
);

CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES tests(test_id),
    client_mac TEXT,
    issue_type TEXT NOT NULL,
    count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES tests(test_id),
    finding_id TEXT NOT NULL,
    severity TEXT,
    observation TEXT,
    metrics_json TEXT
);

CREATE TABLE IF NOT EXISTS reason_codes (
    code INTEGER PRIMARY KEY,
    meaning TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_test ON events(test_id);
CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_mac);
CREATE INDEX IF NOT EXISTS idx_test_clients_client ON test_clients(client_mac);
CREATE INDEX IF NOT EXISTS idx_findings_id ON findings(finding_id);
