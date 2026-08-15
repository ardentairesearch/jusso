use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};

/// Accept ergonomic JSON numbers while keeping decimal processing string-based.
pub(crate) fn deserialize_optional_decimal<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(serde_json::Value::Number(value)) => Ok(Some(value.to_string())),
        Some(_) => Err(D::Error::custom("expected a decimal string or JSON number")),
    }
}
