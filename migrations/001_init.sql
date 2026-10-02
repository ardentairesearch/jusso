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
    allow_raw_execution BOOLEAN NOT NULL DEFAULT FALSE,
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
    UNIQUE (organization_id, external_id),
    UNIQUE (id, organization_id)
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

CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none'
        CHECK (token_endpoint_auth_method = 'none'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE connect_sessions (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    redirect_uri TEXT NOT NULL,
    client_state TEXT,
    code_challenge TEXT NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    resource TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    organization_id UUID REFERENCES organizations(id),
    principal_id UUID REFERENCES principals(id),
    passkey_id UUID,
    selected_agent_id UUID REFERENCES agents(id),
    selected_agent_external_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'authenticated', 'completed', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX idx_connect_sessions_expiry ON connect_sessions(expires_at);

CREATE TABLE owner_accounts (
    principal_id UUID PRIMARY KEY REFERENCES principals(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    owner_handle TEXT NOT NULL,
    owner_handle_normalized TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (principal_id, organization_id)
);
CREATE INDEX idx_owner_accounts_organization ON owner_accounts(organization_id);

CREATE TABLE owner_passkeys (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES owner_accounts(principal_id),
    credential_id TEXT NOT NULL UNIQUE,
    passkey JSONB NOT NULL,
    label TEXT NOT NULL DEFAULT 'Primary passkey',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (id, organization_id, principal_id)
);
CREATE INDEX idx_owner_passkeys_principal ON owner_passkeys(principal_id);

ALTER TABLE connect_sessions
    ADD CONSTRAINT connect_sessions_passkey_id_fkey
    FOREIGN KEY (passkey_id) REFERENCES owner_passkeys(id);

CREATE TABLE oauth_authorization_codes (
    code_hash TEXT PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    connect_session_id UUID NOT NULL UNIQUE REFERENCES connect_sessions(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES principals(id),
    passkey_id UUID NOT NULL REFERENCES owner_passkeys(id),
    agent_id UUID REFERENCES agents(id),
    agent_external_id TEXT,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    resource TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((agent_id IS NULL) = (agent_external_id IS NULL))
);
CREATE INDEX idx_oauth_authorization_codes_expiry
    ON oauth_authorization_codes(expires_at);

CREATE TABLE oauth_connections (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL REFERENCES principals(id),
    passkey_id UUID NOT NULL REFERENCES owner_passkeys(id),
    agent_id UUID REFERENCES agents(id),
    agent_external_id TEXT,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    resource TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    dpop_jkt TEXT CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK ((agent_id IS NULL) = (agent_external_id IS NULL)),
    UNIQUE (id, organization_id, principal_id)
);
CREATE INDEX idx_oauth_connections_principal
    ON oauth_connections(principal_id, created_at DESC);

CREATE TABLE oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    connection_id UUID NOT NULL REFERENCES oauth_connections(id),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    replaced_by_hash TEXT REFERENCES oauth_refresh_tokens(token_hash),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_oauth_refresh_tokens_connection
    ON oauth_refresh_tokens(connection_id, created_at DESC);

CREATE TABLE owner_approval_requests (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    principal_id UUID NOT NULL,
    oauth_connection_id UUID NOT NULL,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    action TEXT NOT NULL CHECK (
        action IN (
            'create_policy', 'assign_policy', 'revoke_policy',
            'create_agent', 'suspend_agent', 'reactivate_agent',
            'rotate_agent_credential', 'rotate_agent_onchain_signer'
        )
    ),
    payload JSONB NOT NULL,
    presentation JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'approved', 'expired')
    ),
    result JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by_passkey_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    CHECK (
        (status = 'approved') =
        (approved_at IS NOT NULL AND approved_by_passkey_id IS NOT NULL AND result IS NOT NULL)
    ),
    CHECK (expires_at > created_at),
    FOREIGN KEY (principal_id, organization_id)
        REFERENCES owner_accounts(principal_id, organization_id),
    FOREIGN KEY (oauth_connection_id, organization_id, principal_id)
        REFERENCES oauth_connections(id, organization_id, principal_id),
    FOREIGN KEY (approved_by_passkey_id, organization_id, principal_id)
        REFERENCES owner_passkeys(id, organization_id, principal_id)
);
CREATE INDEX idx_owner_approval_requests_owner
    ON owner_approval_requests(organization_id, principal_id, created_at DESC);
CREATE INDEX idx_owner_approval_requests_expiry
    ON owner_approval_requests(expires_at) WHERE status = 'pending';

CREATE TABLE turnkey_organization_bindings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    provider_organization_id TEXT UNIQUE,
    sub_organization_name TEXT NOT NULL UNIQUE,
    api_public_key TEXT NOT NULL,
    api_private_key_encrypted TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('provisioning', 'active', 'failed')),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (status = 'active') = (provider_organization_id IS NOT NULL)
    ),
    CHECK (api_public_key ~ '^(02|03)[0-9a-f]{64}$'),
    CHECK (btrim(api_private_key_encrypted) <> ''),
    CHECK (provider_organization_id IS NULL OR btrim(provider_organization_id) <> ''),
    UNIQUE (organization_id, provider_organization_id)
);

CREATE TABLE managed_wallets (
    id UUID PRIMARY KEY,
    wallet_provider TEXT NOT NULL,
    provider_organization_id TEXT NOT NULL,
    provider_wallet_id TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    provider_external_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('infrastructure', 'organization')),
    scope_organization_id UUID REFERENCES organizations(id),
    address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (scope_kind = 'organization' AND scope_organization_id IS NOT NULL)
        OR (scope_kind = 'infrastructure' AND scope_organization_id IS NULL)
    ),
    CHECK (btrim(provider_organization_id) <> ''),
    CHECK (btrim(provider_wallet_id) <> ''),
    CHECK (btrim(provider_account_id) <> ''),
    CHECK (btrim(provider_external_id) <> ''),
    UNIQUE (wallet_provider, provider_wallet_id),
    UNIQUE (wallet_provider, provider_account_id),
    UNIQUE (address),
    UNIQUE (id, scope_organization_id)
);
CREATE UNIQUE INDEX managed_wallets_infrastructure_external_id_key
    ON managed_wallets (wallet_provider, provider_external_id)
    WHERE scope_kind = 'infrastructure';
CREATE UNIQUE INDEX managed_wallets_organization_external_id_key
    ON managed_wallets (wallet_provider, scope_organization_id, provider_external_id)
    WHERE scope_kind = 'organization';
CREATE INDEX managed_wallets_scope_organization_idx
    ON managed_wallets (scope_organization_id)
    WHERE scope_kind = 'organization';

CREATE TABLE agent_wallets (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_uuid UUID NOT NULL UNIQUE,
    managed_wallet_id UUID NOT NULL UNIQUE,
    agent_id TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, agent_id),
    UNIQUE (id, agent_uuid, organization_id),
    FOREIGN KEY (agent_uuid, organization_id)
        REFERENCES agents(id, organization_id),
    FOREIGN KEY (managed_wallet_id, organization_id)
        REFERENCES managed_wallets(id, scope_organization_id)
);
CREATE INDEX idx_agent_wallets_organization ON agent_wallets(organization_id);
CREATE INDEX idx_agent_wallets_address ON agent_wallets(address);

CREATE TABLE agent_smart_accounts (
    agent_wallet_id UUID NOT NULL REFERENCES agent_wallets(id),
    chain_id BIGINT NOT NULL CHECK (chain_id IN (5042, 5042002)),
    account_address TEXT NOT NULL,
    initial_signer_address TEXT NOT NULL,
    account_provider TEXT NOT NULL CHECK (length(trim(account_provider)) > 0),
    provider_account_id TEXT NOT NULL CHECK (length(trim(provider_account_id)) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_wallet_id, chain_id),
    UNIQUE (chain_id, account_address)
);

CREATE TABLE agent_signer_rotations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL,
    agent_wallet_id UUID NOT NULL,
    old_managed_wallet_id UUID NOT NULL,
    replacement_managed_wallet_id UUID,
    old_signer_address TEXT NOT NULL,
    replacement_signer_address TEXT,
    smart_account_address TEXT NOT NULL,
    chain_id BIGINT NOT NULL CHECK (chain_id IN (5042, 5042002)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN (
            'pending', 'provisioned', 'prepared', 'submitted', 'confirmed',
            'reconciled', 'failed', 'recovery_required'
        )
    ),
    signed_user_operation JSONB,
    user_operation_hash TEXT,
    provider_call_id TEXT,
    tx_hash TEXT,
    error_message TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    requested_by_principal_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    FOREIGN KEY (agent_wallet_id, agent_id, organization_id)
        REFERENCES agent_wallets(id, agent_uuid, organization_id),
    FOREIGN KEY (old_managed_wallet_id, organization_id)
        REFERENCES managed_wallets(id, scope_organization_id),
    FOREIGN KEY (replacement_managed_wallet_id, organization_id)
        REFERENCES managed_wallets(id, scope_organization_id),
    FOREIGN KEY (requested_by_principal_id, organization_id)
        REFERENCES owner_accounts(principal_id, organization_id),
    CHECK (
        (replacement_managed_wallet_id IS NULL) =
        (replacement_signer_address IS NULL)
    ),
    CHECK (
        (signed_user_operation IS NULL AND user_operation_hash IS NULL)
        OR (signed_user_operation IS NOT NULL AND user_operation_hash IS NOT NULL)
    ),
    CHECK (
        (status IN ('reconciled', 'failed')) = (completed_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX agent_signer_rotations_one_active_per_agent
    ON agent_signer_rotations(agent_id)
    WHERE status NOT IN ('reconciled', 'failed');
CREATE INDEX agent_signer_rotations_work_queue
    ON agent_signer_rotations(created_at)
    WHERE status NOT IN ('reconciled', 'failed');
CREATE INDEX agent_signer_rotations_owner
    ON agent_signer_rotations(organization_id, requested_by_principal_id, created_at DESC);

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
    signed_user_operation JSONB,
    user_operation_hash TEXT,
    provider_call_id TEXT,
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
    request_id UUID NOT NULL UNIQUE REFERENCES execution_requests(id),
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
    request_id UUID NOT NULL UNIQUE REFERENCES execution_requests(id),
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
