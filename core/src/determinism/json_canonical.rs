//! Canonical JSON uses recursively sorted object keys, compact UTF-8, and integer-only numbers.

use crate::error::{CoreError, CoreResult};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

// Phase_2_5_Lock_Addendum_v2.5-lock-4.md §2.2:
// - UTF-8 JSON (no BOM)
// - keys sorted lexicographically
// - no insignificant whitespace
// - strings JSON-escaped per RFC 8259 (serde_json handles)
// - numbers: integers only (no floats), base-10, no leading zeros
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> CoreResult<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    let normalized = normalize_value(v)?;
    let s = serde_json::to_string(&normalized)?;
    Ok(s.into_bytes())
}

fn normalize_value(v: Value) -> CoreResult<Value> {
    match v {
        Value::Object(map) => {
            let mut btm: BTreeMap<String, Value> = BTreeMap::new();
            for (k, vv) in map {
                btm.insert(k, normalize_value(vv)?);
            }
            // serde_json::Map preserves insertion order; we rebuild in sorted order.
            let mut out = serde_json::Map::new();
            for (k, vv) in btm {
                out.insert(k, vv);
            }
            Ok(Value::Object(out))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for vv in arr {
                out.push(normalize_value(vv)?);
            }
            Ok(Value::Array(out))
        }
        Value::Number(n) => {
            // Enforce integer-only numbers (no floats).
            if n.is_i64() || n.is_u64() {
                Ok(Value::Number(n))
            } else {
                Err(CoreError::DeterminismViolationError(
                    "canonical JSON forbids non-integer numbers".to_string(),
                ))
            }
        }
        other => Ok(other),
    }
}
