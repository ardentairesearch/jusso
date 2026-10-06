ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_token_endpoint_auth_method_check;

ALTER TABLE oauth_clients
    ADD COLUMN jwks_uri TEXT,
    ADD COLUMN token_endpoint_auth_signing_alg TEXT,
    ADD CONSTRAINT oauth_clients_token_endpoint_auth_method_check
        CHECK (token_endpoint_auth_method IN ('none', 'private_key_jwt')),
    ADD CONSTRAINT oauth_clients_authentication_metadata_check
        CHECK (
            (token_endpoint_auth_method = 'none'
                AND jwks_uri IS NULL
                AND token_endpoint_auth_signing_alg IS NULL)
            OR
            (token_endpoint_auth_method = 'private_key_jwt'
                AND jwks_uri IS NOT NULL
                AND token_endpoint_auth_signing_alg IS NOT NULL)
        );
