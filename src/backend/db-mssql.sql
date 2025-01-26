CREATE TABLE jwk
(
    thumbprint VARCHAR(64)   NOT NULL,
    key_type   VARCHAR(16)   NOT NULL,
    algorithm  VARCHAR(16),
    advertise  BIT           NOT NULL DEFAULT 1,
    json       VARCHAR(1024) NOT NULL,
    CONSTRAINT json_is_valid CHECK ( ISJSON(json, OBJECT) = 1 ),
    CONSTRAINT PK_jwks PRIMARY KEY (thumbprint)
);
GO;

CREATE TABLE key_ops
(
    thumbprint VARCHAR(64) NOT NULL,
    op         VARCHAR(8)  NOT NULL,
    CONSTRAINT PK_key_ops PRIMARY KEY (thumbprint, op),
    CONSTRAINT FK_key_ops_jwk FOREIGN KEY (thumbprint)
        REFERENCES jwk (thumbprint) ON UPDATE CASCADE ON DELETE CASCADE
);
GO;
