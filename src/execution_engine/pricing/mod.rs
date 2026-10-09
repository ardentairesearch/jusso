//! Decimal conversion for USD-denominated execution policy and token fees.

use anyhow::{bail, Result};
use ethers_core::types::U256;

pub fn usd_to_token_raw_amount(usd: f64, decimals: u8) -> Result<U256> {
    if !usd.is_finite() || usd < 0.0 || decimals > 18 {
        bail!("invalid USD amount or token decimals");
    }
    let scaled = usd * 10f64.powi(i32::from(decimals));
    if !scaled.is_finite() || !(0.0..=1_000_000_000_000.0).contains(&scaled) {
        bail!("token amount is outside the supported range");
    }
    Ok(U256::from(scaled.ceil() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_up_to_token_units() {
        assert_eq!(usd_to_token_raw_amount(0.000001, 6).unwrap(), U256::one());
        assert_eq!(
            usd_to_token_raw_amount(1.0000001, 6).unwrap(),
            U256::from(1_000_001u64)
        );
        assert!(usd_to_token_raw_amount(f64::NAN, 6).is_err());
        assert!(usd_to_token_raw_amount(-0.01, 6).is_err());
    }
}
