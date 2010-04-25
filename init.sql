CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY,
    name TEXT KEY,
    qclass INTEGER,
    qtype INTEGER,
    ttl INTEGER,
    data BLOB
);

CREATE INDEX responses_name_idx ON responses (name);
