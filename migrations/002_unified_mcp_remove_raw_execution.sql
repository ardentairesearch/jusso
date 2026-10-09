-- Unify all MCP capabilities under the agent-bound /mcp/agent resource and
-- remove the retired arbitrary transaction surface.

UPDATE authorization_policies
SET allowed_actions = array_remove(
        array_remove(allowed_actions, 'transaction:simulate'),
        'transaction:execute'
    ),
    updated_at = now()
WHERE allowed_actions IS NOT NULL;

UPDATE credential_bindings
SET scopes = array_remove(
        array_remove(scopes, 'transaction:simulate'),
        'transaction:execute'
    ),
    updated_at = now();

UPDATE federation_trusts
SET scopes = array_remove(
        array_remove(scopes, 'transaction:simulate'),
        'transaction:execute'
    ),
    updated_at = now();

UPDATE agent_enrollment_grants
SET scopes = array_remove(
        array_remove(scopes, 'transaction:simulate'),
        'transaction:execute'
    );

-- Pending browser state was issued for the old split resource/scope model.
-- Expire it rather than allowing capability changes beneath an authorization.
UPDATE connect_sessions
SET status = 'expired'
WHERE status IN ('pending', 'authenticated');

UPDATE oauth_authorization_codes
SET used_at = now()
WHERE used_at IS NULL;

UPDATE owner_approval_requests
SET status = 'expired'
WHERE status = 'pending';

UPDATE owner_passkey_enrollment_requests
SET status = 'expired'
WHERE status = 'pending';

UPDATE execution_requests
SET status = 'failed',
    error_message = COALESCE(
        error_message,
        'retired external execution quote was invalidated during MCP unification'
    ),
    updated_at = now()
WHERE status = 'payment_required';

-- Existing connections were consented to either the runtime or control
-- resource, not their union. Force a fresh OAuth consent after deployment.
UPDATE oauth_connections
SET status = 'revoked', revoked_at = COALESCE(revoked_at, now()), updated_at = now()
WHERE status = 'active';

ALTER TABLE authorization_policies
DROP COLUMN allow_raw_execution;
