-- Canonical fresh schema for the Jusso Beta.

CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    webhook_secret_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE principals (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    display_name TEXT,
    principal_type TEXT NOT NULL DEFAULT 'agent'
        CHECK (principal_type IN ('owner', 'agent', 'operator')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    auth_version BIGINT NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_principals_organization ON principals(organization_id);

CREATE TABLE authorization_policies (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    allowed_chains TEXT[],
    allowed_protocols TEXT[],
    allowed_actions TEXT[],
    allowed_targets TEXT[],
    max_value_wei TEXT CHECK (max_value_wei IS NULL OR max_value_wei ~ '^[0-9]+$'),
    max_execution_fee_usd DOUBLE PRECISION
        CHECK (max_execution_fee_usd IS NULL OR max_execution_fee_usd >= 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE INDEX idx_auth_policies_org ON authorization_policies(organization_id);

CREATE TABLE agents (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    external_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    parent_agent_id UUID REFERENCES agents(id),
    policy_id UUID NOT NULL REFERENCES authorization_policies(id),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, external_id)
);
CREATE INDEX idx_agents_organization ON agents(organization_id);
CREATE INDEX idx_agents_parent ON agents(parent_agent_id);

CREATE TABLE principal_agent_grants (
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, agent_id)
);
CREATE INDEX idx_principal_agent_grants_agent ON principal_agent_grants(agent_id);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES principals(id),
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    label TEXT,
    scopes TEXT[] NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('live', 'test')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_keys_organization ON api_keys(organization_id);
CREATE INDEX idx_api_keys_principal ON api_keys(principal_id);

CREATE TABLE credential_bindings (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES principals(id),
    agent_id UUID REFERENCES agents(id),
    credential_kind TEXT NOT NULL CHECK (credential_kind IN ('local_jwk')),
    client_id TEXT NOT NULL UNIQUE,
    public_jwk JSONB NOT NULL,
    public_jwk_thumbprint TEXT NOT NULL UNIQUE
        CHECK (public_jwk_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
    scopes TEXT[] NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_credential_bindings_org ON credential_bindings(organization_id);
CREATE INDEX idx_credential_bindings_principal ON credential_bindings(principal_id);
CREATE INDEX idx_credential_bindings_agent ON credential_bindings(agent_id);

CREATE TABLE federation_trusts (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL UNIQUE REFERENCES principals(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    audience TEXT NOT NULL,
    subject_pattern TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (organization_id, name),
    UNIQUE (issuer, audience, subject_pattern)
);
CREATE INDEX idx_federation_trusts_lookup ON federation_trusts(issuer, audience)
    WHERE is_active = TRUE;

CREATE TABLE agent_instances (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    federation_trust_id UUID REFERENCES federation_trusts(id),
    instance_key TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, instance_key)
);
CREATE INDEX idx_agent_instances_agent ON agent_instances(agent_id);

CREATE TABLE agent_enrollment_grants (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    created_by_principal_id UUID NOT NULL REFERENCES principals(id),
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_enrollment_grants_expiry ON agent_enrollment_grants(expires_at);

CREATE TABLE oauth_proof_jtis (
    proof_context TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (proof_context, jti)
);
CREATE INDEX idx_oauth_proof_jtis_expiry ON oauth_proof_jtis(expires_at);

CREATE TABLE managed_wallets (
    id UUID PRIMARY KEY,
    wallet_provider TEXT NOT NULL,
    provider_wallet_id TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    provider_external_id TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (wallet_provider, provider_wallet_id),
    UNIQUE (wallet_provider, provider_account_id),
    UNIQUE (wallet_provider, provider_external_id),
    UNIQUE (address)
);

CREATE TABLE agent_wallets (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_uuid UUID NOT NULL UNIQUE REFERENCES agents(id),
    managed_wallet_id UUID NOT NULL UNIQUE REFERENCES managed_wallets(id),
    agent_id TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, agent_id)
);
CREATE INDEX idx_agent_wallets_organization ON agent_wallets(organization_id);
CREATE INDEX idx_agent_wallets_address ON agent_wallets(address);

CREATE TABLE auth_audit_events (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    principal_id UUID REFERENCES principals(id),
    agent_id UUID REFERENCES agents(id),
    instance_id UUID REFERENCES agent_instances(id),
    credential_id UUID,
    credential_kind TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_audit_events_org_created
    ON auth_audit_events(organization_id, created_at DESC);

CREATE TABLE execution_requests (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES principals(id),
    agent_uuid UUID NOT NULL REFERENCES agents(id),
    instance_id UUID REFERENCES agent_instances(id),
    policy_id UUID NOT NULL REFERENCES authorization_policies(id),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    agent_id TEXT NOT NULL,
    smart_wallet_address TEXT,
    chain TEXT NOT NULL,
    target_contract TEXT NOT NULL,
    calldata TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '0',
    strategy_id TEXT,
    callback_url TEXT,
    payload_hash TEXT NOT NULL,
    idempotency_key TEXT,
    idempotency_fingerprint TEXT,
    gas_estimate BIGINT,
    cost_usd DOUBLE PRECISION,
    status TEXT NOT NULL DEFAULT 'pending',
    tx_hash TEXT,
    error_message TEXT,
    signed_transaction TEXT,
    signed_transaction_hash TEXT,
    transaction_phase_count SMALLINT
        CHECK (transaction_phase_count IS NULL OR transaction_phase_count > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT execution_requests_idempotency_pair CHECK (
        (idempotency_key IS NULL AND idempotency_fingerprint IS NULL)
        OR (
            idempotency_key IS NOT NULL
            AND idempotency_fingerprint ~ '^[0-9a-f]{64}$'
            AND char_length(idempotency_key) BETWEEN 8 AND 128
        )
    )
);
CREATE INDEX idx_exec_req_agent ON execution_requests(agent_uuid, created_at DESC);
CREATE INDEX idx_exec_req_status ON execution_requests(status);
CREATE INDEX idx_execution_requests_payload_hash ON execution_requests(payload_hash);
CREATE INDEX idx_execution_requests_org_id ON execution_requests(organization_id, id);
CREATE UNIQUE INDEX execution_requests_org_idempotency
    ON execution_requests(organization_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE execution_permits (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE REFERENCES execution_requests(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES principals(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    instance_id UUID REFERENCES agent_instances(id),
    policy_id UUID NOT NULL REFERENCES authorization_policies(id),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    wallet_address TEXT NOT NULL,
    chain TEXT NOT NULL,
    execution_fee_raw TEXT CHECK (execution_fee_raw IS NULL OR execution_fee_raw ~ '^[0-9]+$'),
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_execution_permits_expiry ON execution_permits(expires_at);

CREATE TABLE transactions (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES execution_requests(id),
    chain TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    gas_used BIGINT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tx_request ON transactions(request_id);

CREATE TABLE payments (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES execution_requests(id),
    payer TEXT NOT NULL,
    amount_usd DOUBLE PRECISION NOT NULL,
    amount_raw TEXT NOT NULL CHECK (amount_raw ~ '^[0-9]+$'),
    token TEXT NOT NULL,
    token_contract TEXT NOT NULL,
    payment_chain TEXT NOT NULL,
    payment_tx_hash TEXT NOT NULL UNIQUE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_payments_request ON payments(request_id);

CREATE TABLE registration_events (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    principal_id UUID REFERENCES principals(id),
    client_fingerprint TEXT NOT NULL CHECK (client_fingerprint ~ '^[0-9a-f]{64}$'),
    outcome TEXT NOT NULL CHECK (outcome IN ('created', 'rejected')),
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX registration_events_fingerprint_created
    ON registration_events(client_fingerprint, created_at DESC);
