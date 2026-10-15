//! Explicit lock units. Legacy height-only bundles retain their exact encoding;
//! timestamp support does not by itself establish cross-chain deadline safety.
use crate::Result;
use serde_json::{Value, json};

const THRESHOLD: u32 = 500_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundLock {
    Height(u32),
    Timestamp(u32),
}

impl RefundLock {
    pub fn timestamp(value: u32) -> Result<Self> {
        if value < THRESHOLD {
            return Err("timestamp lock below consensus threshold".into());
        }
        Ok(Self::Timestamp(value))
    }

    pub fn parse(container: &Value) -> Result<Self> {
        let number = |v: &Value| -> Result<u32> {
            Ok(u32::try_from(
                v.as_u64().ok_or("integer refund lock required")?,
            )?)
        };
        match (container.get("refund_height"), container.get("refund_lock")) {
            (Some(height), None) => {
                let n = number(height)?;
                if !(1..THRESHOLD).contains(&n) {
                    return Err("height refund lock range".into());
                }
                Ok(Self::Height(n))
            }
            (None, Some(lock)) => {
                if lock.as_object().is_none_or(|o| o.len() != 2) || lock["kind"] != "timestamp" {
                    return Err("unknown refund lock kind/fields".into());
                }
                Self::timestamp(number(&lock["value"])?)
            }
            _ => Err("exactly one unambiguous refund lock required".into()),
        }
    }

    pub fn value(self) -> u32 {
        match self {
            Self::Height(v) | Self::Timestamp(v) => v,
        }
    }

    pub fn required_time(self) -> Option<u32> {
        match self {
            Self::Timestamp(v) => Some(v),
            Self::Height(_) => None,
        }
    }

    pub fn required_height(self) -> Option<u32> {
        match self {
            Self::Height(v) => Some(v),
            Self::Timestamp(_) => None,
        }
    }

    pub fn attach(self, container: &mut Value) {
        match self {
            Self::Height(v) => container["refund_height"] = json!(v),
            Self::Timestamp(v) => container["refund_lock"] = json!({"kind":"timestamp","value":v}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_confused_lock_units_and_preserve_legacy_encoding() {
        for value in [
            json!({}),
            json!({"refund_height":500_000_000}),
            json!({"refund_height":0}),
            json!({"refund_height":true}),
            json!({"refund_lock":{"kind":"timestamp","value":499_999_999}}),
            json!({"refund_lock":{"kind":"timestamp","value":4_294_967_296u64}}),
            json!({"refund_lock":{"kind":"height","value":42}}),
            json!({"refund_lock":{"kind":"timestamp","value":1_700_000_000,"extra":1}}),
            json!({"refund_height":42,"refund_lock":{"kind":"timestamp","value":1_700_000_000}}),
        ] {
            assert!(RefundLock::parse(&value).is_err());
        }
        let legacy = json!({"refund_height":42});
        let lock = RefundLock::parse(&legacy).unwrap();
        let mut encoded = json!({});
        lock.attach(&mut encoded);
        assert_eq!(legacy, encoded);
        assert_eq!(lock.required_height(), Some(42));
        assert_eq!(lock.required_time(), None);
        let time = RefundLock::timestamp(1_700_000_000).unwrap();
        let mut encoded = json!({});
        time.attach(&mut encoded);
        assert_eq!(RefundLock::parse(&encoded).unwrap(), time);
        assert_eq!(time.required_height(), None);
        assert_eq!(time.required_time(), Some(1_700_000_000));
    }
}
