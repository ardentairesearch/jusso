-- Circle Agent Wallet BYOW connections and externally executed payment intents.

CREATE TABLE external_wallet_connection_challenges (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'circle_agent_wallet'),
    chain TEXT NOT NULL CHECK (chain IN ('arc', 'arc-testnet')),
    wallet_address TEXT NOT NULL CHECK (wallet_address ~ '^0x[0-9a-f]{40}$'),
    challenge TEXT NOT NULL UNIQUE CHECK (length(challenge) BETWEEN 32 AND 512),
    created_by_principal_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (agent_id, organization_id) REFERENCES agents(id, organization_id),
    FOREIGN KEY (created_by_principal_id, organization_id)
        REFERENCES principals(id, organization_id)
);
CREATE INDEX external_wallet_challenges_expiry
    ON external_wallet_connection_challenges(expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE external_wallet_connections (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'circle_agent_wallet'),
    chain TEXT NOT NULL CHECK (chain IN ('arc', 'arc-testnet')),
    wallet_address TEXT NOT NULL CHECK (wallet_address ~ '^0x[0-9a-f]{40}$'),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    ownership_challenge TEXT NOT NULL,
    ownership_signature TEXT NOT NULL CHECK (ownership_signature ~ '^0x[0-9a-f]+$'),
    connected_by_principal_id UUID NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (agent_id, organization_id) REFERENCES agents(id, organization_id),
    FOREIGN KEY (connected_by_principal_id, organization_id)
        REFERENCES principals(id, organization_id),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    UNIQUE (id, organization_id)
);
CREATE UNIQUE INDEX external_wallet_connections_active_agent
    ON external_wallet_connections(organization_id, agent_id)
    WHERE status = 'active';
CREATE UNIQUE INDEX external_wallet_connections_active_address
    ON external_wallet_connections(chain, wallet_address)
    WHERE status = 'active';
CREATE INDEX external_wallet_connections_organization
    ON external_wallet_connections(organization_id, created_at DESC);

ALTER TABLE payment_plan_runs DROP CONSTRAINT payment_plan_runs_status_check;
ALTER TABLE payment_plan_runs ADD CONSTRAINT payment_plan_runs_status_check CHECK (
    status IN (
        'claimed', 'processing', 'queued', 'awaiting_wallet',
        'confirmed', 'skipped', 'failed', 'reverted'
    )
);

CREATE TABLE external_wallet_payment_intents (
    id UUID PRIMARY KEY,
    payment_plan_run_id UUID NOT NULL UNIQUE REFERENCES payment_plan_runs(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL,
    connection_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('arc', 'arc-testnet')),
    wallet_address TEXT NOT NULL CHECK (wallet_address ~ '^0x[0-9a-f]{40}$'),
    token_address TEXT NOT NULL CHECK (token_address ~ '^0x[0-9a-f]{40}$'),
    transfers JSONB NOT NULL CHECK (jsonb_typeof(transfers) = 'array'),
    total_amount_raw NUMERIC(78, 0) NOT NULL CHECK (total_amount_raw > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'confirmed', 'expired', 'failed')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at TIMESTAMPTZ,
    FOREIGN KEY (agent_id, organization_id) REFERENCES agents(id, organization_id),
    FOREIGN KEY (connection_id, organization_id)
        REFERENCES external_wallet_connections(id, organization_id),
    CHECK ((status = 'confirmed') = (confirmed_at IS NOT NULL))
);
CREATE INDEX external_wallet_payment_intents_pending
    ON external_wallet_payment_intents(organization_id, agent_id, created_at)
    WHERE status = 'pending';

CREATE TABLE external_wallet_intent_transactions (
    intent_id UUID NOT NULL REFERENCES external_wallet_payment_intents(id),
    position SMALLINT NOT NULL CHECK (position BETWEEN 0 AND 15),
    tx_hash TEXT NOT NULL UNIQUE CHECK (tx_hash ~ '^0x[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (intent_id, position)
);

-- Pending approvals serialized before this release do not know about the new
-- wallet actions or presentation format. Require a fresh review.
UPDATE owner_approval_requests
SET status = 'expired'
WHERE status = 'pending';
