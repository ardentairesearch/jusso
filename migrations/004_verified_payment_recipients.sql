-- Human-readable, onchain-verified payment recipients.

ALTER TABLE payment_plan_recipients RENAME COLUMN label TO recipient_name;
ALTER TABLE payment_plan_recipients
    ADD COLUMN address_kind TEXT CHECK (address_kind IN ('wallet', 'contract')),
    ADD COLUMN verified_at TIMESTAMPTZ;

CREATE TABLE payment_recipient_contacts (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    chain TEXT NOT NULL CHECK (chain IN ('arc', 'arc-testnet')),
    recipient_address TEXT NOT NULL CHECK (recipient_address ~ '^0x[0-9a-f]{40}$'),
    recipient_name TEXT NOT NULL CHECK (length(trim(recipient_name)) BETWEEN 1 AND 80),
    address_kind TEXT NOT NULL CHECK (address_kind IN ('wallet', 'contract')),
    verified_at TIMESTAMPTZ NOT NULL,
    created_by_principal_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (created_by_principal_id, organization_id)
        REFERENCES principals(id, organization_id),
    UNIQUE (organization_id, chain, recipient_address)
);
CREATE INDEX payment_recipient_contacts_organization
    ON payment_recipient_contacts(organization_id, recipient_name);

-- Pending approvals use the previous recipient payload and review format.
UPDATE owner_approval_requests
SET status = 'expired'
WHERE status = 'pending';
