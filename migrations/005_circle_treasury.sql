-- Circle Swap/Earn autonomy controls and durable operation idempotency.

-- Keep owner-reviewed wallet and treasury actions inside the database trust
-- boundary. The BYOW migration introduced its action variants without
-- widening this original allowlist, so repair those variants here as well.
ALTER TABLE owner_approval_requests
    DROP CONSTRAINT owner_approval_requests_action_check;
ALTER TABLE owner_approval_requests
    ADD CONSTRAINT owner_approval_requests_action_check CHECK (
        action IN (
            'create_policy', 'update_policy', 'assign_policy', 'revoke_policy',
            'create_agent', 'suspend_agent', 'reactivate_agent',
            'rotate_agent_credential', 'rotate_agent_onchain_signer',
            'revoke_owner_passkey', 'connect_circle_agent_wallet',
            'revoke_external_wallet', 'configure_treasury',
            'create_payment_plan', 'update_payment_plan',
            'change_payment_plan_status'
        )
    );

-- New typed capabilities remain inert until an owner approves treasury
-- settings. Extend only the generated default policy; custom policies keep
-- their deliberately narrower action sets.
UPDATE authorization_policies
SET allowed_actions = (
        SELECT array_agg(DISTINCT action ORDER BY action)
        FROM unnest(
            allowed_actions || ARRAY['swap:execute', 'earn:deposit', 'earn:withdraw']
        ) AS action
    ),
    updated_at = now()
WHERE name = 'default-autonomous'
  AND allowed_actions IS NOT NULL;

-- EURC is the default conversion asset. It has six decimals like USDC, so the
-- generated policy's conservative per-action and rolling limits can be reused.
UPDATE authorization_policies
SET token_spend_limits = token_spend_limits || jsonb_build_array(
        jsonb_build_object(
            'token', '0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a',
            'max_per_execution_raw', '500000000',
            'max_rolling_raw', '2500000000'
        ),
        jsonb_build_object(
            'token', '0xbEf5f6d51CB62b58e6A8f77868681825C6fe21c1',
            'max_per_execution_raw', '500000000',
            'max_rolling_raw', '2500000000'
        )
    ),
    updated_at = now()
WHERE name = 'default-autonomous'
  AND jsonb_typeof(token_spend_limits) = 'array'
  AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(token_spend_limits) AS token_limit
      WHERE lower(token_limit->>'token') IN (
          lower('0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a'),
          lower('0xbEf5f6d51CB62b58e6A8f77868681825C6fe21c1')
      )
  );

CREATE TABLE agent_treasury_settings (
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    swaps_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    earn_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    max_swap_usdc_raw NUMERIC(78, 0) NOT NULL DEFAULT 0
        CHECK (max_swap_usdc_raw >= 0),
    max_slippage_bps INTEGER NOT NULL DEFAULT 100
        CHECK (max_slippage_bps BETWEEN 10 AND 500),
    minimum_liquid_usdc_raw NUMERIC(78, 0) NOT NULL DEFAULT 0
        CHECK (minimum_liquid_usdc_raw >= 0),
    max_earn_allocation_usdc_raw NUMERIC(78, 0) NOT NULL DEFAULT 0
        CHECK (max_earn_allocation_usdc_raw >= 0),
    allowed_earn_vaults TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, agent_id),
    FOREIGN KEY (agent_id, organization_id) REFERENCES agents(id, organization_id),
    CHECK (NOT swaps_enabled OR max_swap_usdc_raw > 0),
    CHECK (
        NOT earn_enabled
        OR (max_earn_allocation_usdc_raw > 0 AND cardinality(allowed_earn_vaults) > 0)
    )
);

CREATE TABLE treasury_operations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN ('swap_to_usdc', 'earn_deposit', 'earn_withdraw')),
    client_request_id TEXT NOT NULL CHECK (length(client_request_id) BETWEEN 8 AND 128),
    request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL
        CHECK (status IN ('preparing', 'queued', 'confirmed', 'failed', 'reverted')),
    provider_execution_id TEXT,
    execution_request_id UUID REFERENCES execution_requests(id),
    result JSONB,
    error_message TEXT,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (agent_id, organization_id) REFERENCES agents(id, organization_id),
    UNIQUE (organization_id, agent_id, client_request_id)
);
CREATE INDEX treasury_operations_execution_request
    ON treasury_operations(execution_request_id)
    WHERE execution_request_id IS NOT NULL;
