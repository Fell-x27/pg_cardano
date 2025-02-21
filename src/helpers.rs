use hex;
use indexmap::IndexMap;
use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_cbor::{self, Value as CborValue};

pub fn is_valid_hex(s: &str) -> bool {
    s.len() > 2 && s.starts_with("\\x") && s[2..].chars().all(|c| c.is_digit(16))
}

pub fn transform_json(value: JsonValue) -> CborValue {
    match value {
        JsonValue::String(s) => {
            if s.is_empty() || s == "\\x" || s == "0x" {
                CborValue::Bytes(vec![])
            } else if is_valid_hex(&s) {
                let bytes = hex::decode(&s[2..]).expect("Invalid hex string");
                CborValue::Bytes(bytes)
            } else {
                CborValue::Text(s)
            }
        }
        JsonValue::Object(obj) => {
            let transformed_obj = obj
                .into_iter()
                .map(|(k, v)| {
                    let key = if let Ok(num) = k.parse::<i64>() {
                        CborValue::Integer(num as i128)
                    } else {
                        CborValue::Text(k)
                    };
                    (key, transform_json(v))
                })
                .collect();
            CborValue::Map(transformed_obj)
        }
        JsonValue::Array(arr) => CborValue::Array(arr.into_iter().map(transform_json).collect()),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                CborValue::Integer(i as i128)
            } else {
                CborValue::Float(n.as_f64().unwrap())
            }
        }
        JsonValue::Bool(b) => CborValue::Bool(b),
        JsonValue::Null => CborValue::Null,
    }
}

pub fn cbor_to_json(value: CborValue) -> JsonValue {
    match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(b) => JsonValue::Bool(b),
        CborValue::Integer(i) => JsonValue::Number(serde_json::Number::from(i as i64)),
        CborValue::Float(f) => {
            JsonValue::Number(serde_json::Number::from_f64(f).expect("Invalid float value"))
        }
        CborValue::Bytes(b) => {
            if let Ok(nested_cbor) = serde_cbor::from_slice::<CborValue>(&b) {
                cbor_to_json(nested_cbor)
            } else {
                JsonValue::String(format!("\\x{}", hex::encode(b)))
            }
        }
        CborValue::Text(t) => {
            let sanitized_text: String = t.chars().filter(|&c| c != '\u{0}').collect();
            JsonValue::String(sanitized_text)
        }
        CborValue::Array(arr) => {
            JsonValue::Array(arr.into_iter().map(cbor_to_json).collect())
        }
        CborValue::Map(map) => {
            let mut ordered_map = IndexMap::new();
            for (k, v) in map {
                let key = match k {
                    CborValue::Text(t) => t,
                    CborValue::Bytes(b) => format!("\\x{}", hex::encode(b)),
                    CborValue::Integer(i) => i.to_string(),
                    _ => format!("\\x{}", hex::encode(serde_cbor::to_vec(&k).unwrap())),
                };
                ordered_map.insert(key, cbor_to_json(v));
            }
            eprintln!("Ordered JSON object: {:?}", ordered_map.keys().collect::<Vec<_>>());
            JsonValue::Object(serde_json::Map::from_iter(ordered_map.into_iter()))
        }
        _ => JsonValue::String(format!("\\x{}", hex::encode(serde_cbor::to_vec(&value).unwrap()))),
    }
}

pub fn helper_shelley_addr_extract_main_cred(
    bech32_decode_data: impl Fn(&str) -> Vec<u8>,
    addr_bech32: &str,
) -> Vec<u8> {
    let raw_address = bech32_decode_data(addr_bech32);
    if raw_address.len() < 29 {
        panic!(
            "Invalid address length: {}. Expected at least 29 bytes.",
            raw_address.len()
        );
    }
    raw_address[1..29].to_vec()
}

pub fn helper_shelley_addr_extract_additional_cred(
    bech32_decode_data: impl Fn(&str) -> Vec<u8>,
    addr_bech32: &str,
) -> Vec<u8> {
    let raw_address = bech32_decode_data(addr_bech32);
    if raw_address.len() != 57 {
        panic!(
            "Invalid address length: {}. Expected 57 bytes.",
            raw_address.len()
        );
    }
    raw_address[29..57].to_vec()
}
