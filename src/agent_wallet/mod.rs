//! Provider-backed agent wallet registry.
//!
//! Jusso persists only provider references and public addresses. The wallet
//! provider owns the private keys. This registry holds the Turnkey signer;
//! the agent's fundable Arc smart account is resolved separately.

use anyhow::{anyhow, Context, Result};
use ethers::types::Address;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::wallet_provider::{
    deterministic_wallet_name, validate_provider_wallet, ManagedWallet, ProviderWallet,
    WalletManager, WalletProviderKind, WalletScope,
};

#[derive(Clone)]
pub struct AgentWallet {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_uuid: Uuid,
    pub agent_id: String,
    pub address: Address,
    pub managed_wallet: ManagedWallet,
}

impl std::fmt::Debug for AgentWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentWallet")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("agent_uuid", &self.agent_uuid)
            .field("agent_id", &self.agent_id)
            .field("address", &self.address)
            .field("provider", &self.managed_wallet.provider_wallet.provider)
            .field(
                "provider_wallet_id",
                &self.managed_wallet.provider_wallet.provider_wallet_id,
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct AgentWalletRegistry {
    db_pool: PgPool,
    wallet_manager: WalletManager,
}

impl std::fmt::Debug for AgentWalletRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentWalletRegistry")
            .field("wallet_manager", &self.wallet_manager)
            .finish()
    }
}

impl AgentWalletRegistry {
    pub fn new(db_pool: PgPool, wallet_manager: WalletManager) -> Self {
        Self {
            db_pool,
            wallet_manager,
        }
    }

    pub fn wallet_manager(&self) -> &WalletManager {
        &self.wallet_manager
    }

    pub async fn get_or_create(
        &self,
        organization_id: Uuid,
        agent_id: &str,
    ) -> Result<AgentWallet> {
        validate_agent_id(agent_id)?;
        if let Some(wallet) = self.load_wallet(organization_id, agent_id).await? {
            return Ok(wallet);
        }
        self.provision_wallet(organization_id, agent_id).await
    }

    pub async fn get_existing(
        &self,
        organization_id: Uuid,
        agent_id: &str,
    ) -> Result<Option<AgentWallet>> {
        validate_agent_id(agent_id)?;
        self.load_wallet(organization_id, agent_id).await
    }

    async fn load_wallet(
        &self,
        organization_id: Uuid,
        agent_id: &str,
    ) -> Result<Option<AgentWallet>> {
        let rotation_active = crate::db::agent_has_unresolved_signer_rotation(
            &self.db_pool,
            organization_id,
            agent_id,
        )
        .await?;
        if rotation_active {
            anyhow::bail!(
                "agent execution is paused while its onchain signer rotation is unresolved"
            );
        }
        let row = sqlx::query_as::<_, AgentWalletRow>(
            r#"
            SELECT
                aw.id,
                aw.organization_id,
                aw.agent_uuid,
                aw.agent_id,
                aw.address,
                mw.id AS managed_wallet_id,
                mw.wallet_provider,
                mw.provider_organization_id,
                mw.provider_wallet_id,
                mw.provider_account_id,
                mw.provider_external_id,
                mw.scope_kind,
                mw.scope_organization_id,
                mw.address AS managed_wallet_address
            FROM agent_wallets aw
            JOIN agents a ON a.id = aw.agent_uuid
            JOIN managed_wallets mw ON mw.id = aw.managed_wallet_id
            WHERE aw.organization_id = $1
              AND aw.agent_id = $2
              AND a.status = 'active'
            "#,
        )
        .bind(organization_id)
        .bind(agent_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(AgentWallet::try_from).transpose()
    }

    async fn provision_wallet(&self, organization_id: Uuid, agent_id: &str) -> Result<AgentWallet> {
        let provider_external_id = deterministic_wallet_name(organization_id, agent_id);
        let agent_uuid =
            crate::db::get_agent_by_external_id(&self.db_pool, organization_id, agent_id)
                .await?
                .ok_or_else(|| anyhow!("active agent is not registered in this organization"))?
                .id;
        let managed_wallet = self
            .wallet_manager
            .get_or_create(
                WalletScope::Organization(organization_id),
                &provider_external_id,
            )
            .await
            .context("managed wallet provisioning failed")?;

        let wallet_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO agent_wallets (
                id, organization_id, agent_uuid, managed_wallet_id,
                agent_id, address, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, now())
            ON CONFLICT (organization_id, agent_id) DO NOTHING
            "#,
        )
        .bind(wallet_id)
        .bind(organization_id)
        .bind(agent_uuid)
        .bind(managed_wallet.id)
        .bind(agent_id)
        .bind(format!("{:?}", managed_wallet.provider_wallet.address))
        .execute(&self.db_pool)
        .await?;

        let wallet = self
            .load_wallet(organization_id, agent_id)
            .await?
            .ok_or_else(|| anyhow!("wallet disappeared after provisioning"))?;
        if wallet.address != managed_wallet.provider_wallet.address
            || wallet.managed_wallet.id != managed_wallet.id
        {
            anyhow::bail!("concurrent wallet provisioning returned conflicting account data");
        }
        info!(
            organization_id = %organization_id,
            agent_id,
            address = %managed_wallet.provider_wallet.address,
            provider = %managed_wallet.provider_wallet.provider.as_str(),
            "provisioned provider-backed native account"
        );
        Ok(wallet)
    }
}

impl TryFrom<AgentWalletRow> for AgentWallet {
    type Error = anyhow::Error;

    fn try_from(row: AgentWalletRow) -> Result<Self> {
        if row.wallet_provider != WalletProviderKind::Turnkey.as_str() {
            anyhow::bail!("unsupported wallet provider in database");
        }
        if row.scope_kind != "organization"
            || row.scope_organization_id != Some(row.organization_id)
        {
            anyhow::bail!("agent wallet is bound to the wrong custody scope");
        }
        let address: Address = row
            .address
            .parse()
            .context("corrupt Turnkey signer address in database")?;
        let managed_wallet_address: Address = row
            .managed_wallet_address
            .parse()
            .context("corrupt managed_wallet_address in database")?;
        if address != managed_wallet_address {
            anyhow::bail!("agent and managed wallet addresses do not match");
        }
        let managed_wallet = ManagedWallet {
            id: row.managed_wallet_id,
            provider_wallet: ProviderWallet {
                provider: WalletProviderKind::Turnkey,
                scope: WalletScope::Organization(row.organization_id),
                provider_organization_id: row.provider_organization_id,
                provider_wallet_id: row.provider_wallet_id,
                provider_account_id: row.provider_account_id,
                external_id: row.provider_external_id,
                address: managed_wallet_address,
            },
        };
        validate_provider_wallet(
            &managed_wallet.provider_wallet,
            WalletProviderKind::Turnkey,
            WalletScope::Organization(row.organization_id),
            &managed_wallet.provider_wallet.external_id,
        )?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            agent_uuid: row.agent_uuid,
            agent_id: row.agent_id,
            address,
            managed_wallet,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct AgentWalletRow {
    id: Uuid,
    organization_id: Uuid,
    agent_uuid: Uuid,
    agent_id: String,
    address: String,
    managed_wallet_id: Uuid,
    wallet_provider: String,
    provider_organization_id: String,
    provider_wallet_id: String,
    provider_account_id: String,
    provider_external_id: String,
    scope_kind: String,
    scope_organization_id: Option<Uuid>,
    managed_wallet_address: String,
}

fn validate_agent_id(agent_id: &str) -> Result<()> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed != agent_id {
        anyhow::bail!("agent_id must contain 1-128 characters without surrounding whitespace");
    }
    if agent_id.chars().any(char::is_control) {
        anyhow::bail!("agent_id cannot contain control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ethers::types::{Signature, H256};
    use std::sync::Arc;

    #[derive(Debug)]
    struct ProvisioningProvider {
        address: Address,
    }

    #[async_trait]
    impl crate::wallet_provider::WalletProvider for ProvisioningProvider {
        fn kind(&self) -> WalletProviderKind {
            WalletProviderKind::Turnkey
        }

        async fn find_wallet(
            &self,
            _scope: WalletScope,
            _external_id: &str,
        ) -> Result<Option<ProviderWallet>> {
            Ok(None)
        }

        async fn create_wallet(
            &self,
            scope: WalletScope,
            external_id: &str,
        ) -> Result<ProviderWallet> {
            Ok(ProviderWallet {
                provider: WalletProviderKind::Turnkey,
                scope,
                provider_organization_id: "11111111-1111-1111-1111-111111111111".into(),
                provider_wallet_id: format!("provider-wallet-{external_id}"),
                provider_account_id: format!("provider-account-{external_id}"),
                external_id: external_id.to_string(),
                address: self.address,
            })
        }

        async fn sign_hash(
            &self,
            _wallet: &ProviderWallet,
            _hash: H256,
            _idempotency_key: Uuid,
        ) -> Result<Signature> {
            unreachable!("not used by provisioning test")
        }
    }

    #[test]
    fn validates_agent_ids_at_the_wallet_boundary() {
        assert!(validate_agent_id("trader-01").is_ok());
        assert!(validate_agent_id("").is_err());
        assert!(validate_agent_id(" padded").is_err());
        assert!(validate_agent_id("line\nbreak").is_err());
        assert!(validate_agent_id(&"a".repeat(129)).is_err());
    }

    #[tokio::test]
    async fn provisions_and_reloads_one_organization_owned_signer() {
        dotenvy::dotenv().ok();
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::db::create_pool(&database_url).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();

        let organization_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO organizations (id, name, webhook_secret_encrypted) VALUES ($1, $2, $3)",
        )
        .bind(organization_id)
        .bind("Jusso account test")
        .bind("test-only")
        .execute(&pool)
        .await
        .unwrap();
        let policy_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO authorization_policies (id, organization_id, name) VALUES ($1, $2, $3)",
        )
        .bind(policy_id)
        .bind(organization_id)
        .bind(format!("wallet-test-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agents (id, organization_id, external_id, display_name, policy_id) VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(organization_id)
        .bind("native-agent")
        .bind(policy_id)
        .execute(&pool)
        .await
        .unwrap();

        let address =
            Address::from_slice(&ethers::utils::keccak256(organization_id.as_bytes())[..20]);
        let manager = WalletManager::new(pool.clone(), Arc::new(ProvisioningProvider { address }));
        let registry = AgentWalletRegistry::new(pool.clone(), manager);

        let created = registry
            .get_or_create(organization_id, "native-agent")
            .await
            .unwrap();
        let loaded = registry
            .get_or_create(organization_id, "native-agent")
            .await
            .unwrap();

        assert_eq!(created.id, loaded.id);
        assert_eq!(created.address, address);
        assert_eq!(loaded.managed_wallet.id, created.managed_wallet.id);
        let account_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_wallets WHERE organization_id = $1")
                .bind(organization_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(account_count, 1);
    }
}
