//! Provider-neutral custody boundary for managed EVM wallets.
//!
//! Provider keys remain with the configured custody service. Jusso stores
//! only opaque provider identifiers and public addresses.

mod turnkey;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ethers::types::{Address, Signature, H256};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::{fmt, str::FromStr, sync::Arc};
use uuid::Uuid;

pub use turnkey::TurnkeyWalletProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletProviderKind {
    Turnkey,
}

impl WalletProviderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Turnkey => "turnkey",
        }
    }
}

impl FromStr for WalletProviderKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "turnkey" => Ok(Self::Turnkey),
            _ => bail!("unsupported wallet provider {value:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderWallet {
    pub provider: WalletProviderKind,
    pub provider_wallet_id: String,
    pub provider_account_id: String,
    pub external_id: String,
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWallet {
    pub id: Uuid,
    pub provider_wallet: ProviderWallet,
}

#[async_trait]
pub trait WalletProvider: Send + Sync {
    fn kind(&self) -> WalletProviderKind;

    async fn find_wallet(&self, external_id: &str) -> Result<Option<ProviderWallet>>;

    async fn create_wallet(&self, external_id: &str) -> Result<ProviderWallet>;

    async fn sign_hash(
        &self,
        wallet: &ProviderWallet,
        hash: H256,
        idempotency_key: Uuid,
    ) -> Result<Signature>;
}

#[derive(Clone)]
pub struct WalletManager {
    db_pool: PgPool,
    provider: Arc<dyn WalletProvider>,
}

impl fmt::Debug for WalletManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletManager")
            .field("provider", &self.provider.kind())
            .finish()
    }
}

impl WalletManager {
    pub fn new(db_pool: PgPool, provider: Arc<dyn WalletProvider>) -> Self {
        Self { db_pool, provider }
    }

    pub async fn get_or_create(&self, external_id: &str) -> Result<ManagedWallet> {
        validate_external_id(external_id)?;
        let mut tx = self.db_pool.begin().await?;
        lock_external_id(&mut tx, self.provider.kind(), external_id).await?;

        if let Some(wallet) =
            load_managed_wallet(&mut tx, self.provider.kind(), external_id).await?
        {
            tx.commit().await?;
            return Ok(wallet);
        }

        let provider_wallet = match self.provider.find_wallet(external_id).await? {
            Some(wallet) => wallet,
            None => self.provider.create_wallet(external_id).await?,
        };
        validate_provider_wallet(&provider_wallet, self.provider.kind(), external_id)?;

        let wallet = ManagedWallet {
            id: Uuid::new_v4(),
            provider_wallet,
        };
        sqlx::query(
            r#"
            INSERT INTO managed_wallets (
                id, wallet_provider, provider_wallet_id, provider_account_id,
                provider_external_id, address, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, now())
            "#,
        )
        .bind(wallet.id)
        .bind(wallet.provider_wallet.provider.as_str())
        .bind(&wallet.provider_wallet.provider_wallet_id)
        .bind(&wallet.provider_wallet.provider_account_id)
        .bind(&wallet.provider_wallet.external_id)
        .bind(format!("{:?}", wallet.provider_wallet.address))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(wallet)
    }

    pub async fn sign_hash(
        &self,
        wallet: &ManagedWallet,
        hash: H256,
        idempotency_key: Uuid,
    ) -> Result<Signature> {
        validate_provider_wallet(
            &wallet.provider_wallet,
            self.provider.kind(),
            &wallet.provider_wallet.external_id,
        )?;
        let signature = self
            .provider
            .sign_hash(&wallet.provider_wallet, hash, idempotency_key)
            .await?;
        let recovered = signature
            .recover(hash)
            .context("wallet-provider signature recovery failed")?;
        if recovered != wallet.provider_wallet.address {
            bail!(
                "wallet-provider signature mismatch: expected {:?}, recovered {recovered:?}",
                wallet.provider_wallet.address
            );
        }
        Ok(signature)
    }
}

async fn lock_external_id(
    tx: &mut Transaction<'_, Postgres>,
    provider: WalletProviderKind,
    external_id: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{}:{external_id}", provider.as_str()))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn load_managed_wallet(
    tx: &mut Transaction<'_, Postgres>,
    provider: WalletProviderKind,
    external_id: &str,
) -> Result<Option<ManagedWallet>> {
    let row = sqlx::query_as::<_, ManagedWalletRow>(
        r#"
        SELECT id, wallet_provider, provider_wallet_id, provider_account_id,
               provider_external_id, address
        FROM managed_wallets
        WHERE wallet_provider = $1 AND provider_external_id = $2
        "#,
    )
    .bind(provider.as_str())
    .bind(external_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(ManagedWallet::try_from).transpose()
}

pub(crate) fn validate_provider_wallet(
    wallet: &ProviderWallet,
    expected_provider: WalletProviderKind,
    expected_external_id: &str,
) -> Result<()> {
    validate_external_id(&wallet.external_id)?;
    if wallet.provider != expected_provider {
        bail!("wallet provider returned the wrong provider kind");
    }
    if wallet.external_id != expected_external_id {
        bail!("wallet provider returned the wrong external identifier");
    }
    if wallet.provider_wallet_id.trim().is_empty() || wallet.provider_account_id.trim().is_empty() {
        bail!("wallet provider returned an empty opaque identifier");
    }
    if wallet.address == Address::zero() {
        bail!("wallet provider returned the zero address");
    }
    Ok(())
}

pub fn deterministic_wallet_name(organization_id: Uuid, agent_id: &str) -> String {
    let digest = Sha256::digest(format!("{organization_id}:{agent_id}").as_bytes());
    format!("jusso-{}", &hex::encode(digest)[..28])
}

pub fn validate_external_id(external_id: &str) -> Result<()> {
    let valid = (2..=64).contains(&external_id.len())
        && external_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (byte == b'-' && index > 0 && index + 1 < external_id.len())
        });
    if !valid {
        bail!("wallet external identifier is invalid");
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct ManagedWalletRow {
    id: Uuid,
    wallet_provider: String,
    provider_wallet_id: String,
    provider_account_id: String,
    provider_external_id: String,
    address: String,
}

impl TryFrom<ManagedWalletRow> for ManagedWallet {
    type Error = anyhow::Error;

    fn try_from(row: ManagedWalletRow) -> Result<Self> {
        let provider = WalletProviderKind::from_str(&row.wallet_provider)?;
        let wallet = Self {
            id: row.id,
            provider_wallet: ProviderWallet {
                provider,
                provider_wallet_id: row.provider_wallet_id,
                provider_account_id: row.provider_account_id,
                external_id: row.provider_external_id,
                address: row
                    .address
                    .parse()
                    .context("corrupt managed-wallet address in database")?,
            },
        };
        validate_provider_wallet(
            &wallet.provider_wallet,
            provider,
            &wallet.provider_wallet.external_id,
        )?;
        Ok(wallet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::LocalWallet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct TestProvider {
        signer: LocalWallet,
    }

    #[derive(Debug)]
    struct ProvisioningProvider {
        address: Address,
        find_calls: AtomicUsize,
        create_calls: AtomicUsize,
    }

    #[async_trait]
    impl WalletProvider for TestProvider {
        fn kind(&self) -> WalletProviderKind {
            WalletProviderKind::Turnkey
        }

        async fn find_wallet(&self, _external_id: &str) -> Result<Option<ProviderWallet>> {
            unreachable!("not used by signing tests")
        }

        async fn create_wallet(&self, _external_id: &str) -> Result<ProviderWallet> {
            unreachable!("not used by signing tests")
        }

        async fn sign_hash(
            &self,
            _wallet: &ProviderWallet,
            hash: H256,
            _idempotency_key: Uuid,
        ) -> Result<Signature> {
            self.signer.sign_hash(hash).map_err(Into::into)
        }
    }

    #[async_trait]
    impl WalletProvider for ProvisioningProvider {
        fn kind(&self) -> WalletProviderKind {
            WalletProviderKind::Turnkey
        }

        async fn find_wallet(&self, _external_id: &str) -> Result<Option<ProviderWallet>> {
            self.find_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        async fn create_wallet(&self, external_id: &str) -> Result<ProviderWallet> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProviderWallet {
                provider: WalletProviderKind::Turnkey,
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
            unreachable!("not used by provisioning tests")
        }
    }

    #[test]
    fn deterministic_names_are_stable_and_provider_safe() {
        let organization_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let first = deterministic_wallet_name(organization_id, "trader");
        assert_eq!(first, deterministic_wallet_name(organization_id, "trader"));
        assert_ne!(
            first,
            deterministic_wallet_name(organization_id, "other-agent")
        );
        validate_external_id(&first).unwrap();
    }

    #[test]
    fn external_ids_reject_ambiguous_or_unsafe_values() {
        for invalid in ["a", "-bad", "bad-", "bad_name", "a/path", " space"] {
            assert!(validate_external_id(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn manager_rejects_a_signature_from_the_wrong_provider_wallet() {
        let signer: LocalWallet =
            "0x59c6995e998f97a5a0044976f7d2a5f7c5c0b9d1d7f6f32ca2d6f39bd2f1e8bb"
                .parse()
                .unwrap();
        let provider = Arc::new(TestProvider { signer });
        let pool = PgPool::connect_lazy("postgres://unused:unused@localhost/unused").unwrap();
        let manager = WalletManager::new(pool, provider);
        let wallet = ManagedWallet {
            id: Uuid::new_v4(),
            provider_wallet: ProviderWallet {
                provider: WalletProviderKind::Turnkey,
                provider_wallet_id: "wallet-id".into(),
                provider_account_id: "account-id".into(),
                external_id: "wallet-name".into(),
                address: Address::from_low_u64_be(1),
            },
        };
        let result = manager
            .sign_hash(&wallet, H256::from_low_u64_be(2), Uuid::new_v4())
            .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature mismatch"));
    }

    #[tokio::test]
    async fn manager_persists_and_reuses_provider_wallet_references() {
        dotenvy::dotenv().ok();
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::db::create_pool(&database_url).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();

        let unique = Uuid::new_v4();
        let external_id = format!("wallet-{unique}");
        let address = Address::from_slice(&Sha256::digest(unique.as_bytes())[..20]);
        let provider = Arc::new(ProvisioningProvider {
            address,
            find_calls: AtomicUsize::new(0),
            create_calls: AtomicUsize::new(0),
        });
        let manager = WalletManager::new(pool, provider.clone());

        let created = manager.get_or_create(&external_id).await.unwrap();
        let loaded = manager.get_or_create(&external_id).await.unwrap();

        assert_eq!(created, loaded);
        assert_eq!(created.provider_wallet.address, address);
        assert_eq!(provider.find_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 1);
    }
}
