CREATE TABLE jwk
(
    thumbprint VARCHAR(64) NOT NULL,
    key_type   VARCHAR(16) NOT NULL,
    algorithm  VARCHAR(16),
    advertise  BOOLEAN     NOT NULL DEFAULT TRUE,
    json       JSONB       NOT NULL,
    CONSTRAINT PK_jwks PRIMARY KEY (thumbprint)
);

CREATE TABLE key_ops
(
    thumbprint VARCHAR(64) NOT NULL,
    op         VARCHAR(8)  NOT NULL,
    CONSTRAINT PK_key_ops PRIMARY KEY (thumbprint, op),
    CONSTRAINT FK_key_ops_jwk FOREIGN KEY (thumbprint)
        REFERENCES jwk (thumbprint) ON UPDATE CASCADE ON DELETE CASCADE
);
