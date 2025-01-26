CREATE TABLE IF NOT EXISTS jwk
(
    thumbprint TEXT    NOT NULL,
    key_type   TEXT    NOT NULL,
    algorithm  TEXT    NOT,
    advertise  INTEGER NOT NULL DEFAULT TRUE,
    json       TEXT    NOT NULL CHECK ( valid_json(json) = 1 ),
    CONSTRAINT PK_jwks PRIMARY KEY (thumbprint)
) STRICT;

CREATE TABLE IF NOT EXISTS key_op
(
    key_id TEXT NOT NULL,
    op     TEXT NOT NULL,
    CONSTRAINT PK_key_ops PRIMARY KEY (key_id, op),
    CONSTRAINT FK_key_ops_jwk FOREIGN KEY (key_id) REFERENCES jwk (thumbprint)
) STRICT;
