use hex;
use serde_cbor::{self, Value as CborValue};
use serde_json::{Value as JsonValue};

pub fn transform_json(value: JsonValue) -> CborValue {
    match value {
        JsonValue::String(s) => {
            if s.is_empty() || matches!(s.as_str(), "\\x" | "0x") {
                return CborValue::Bytes(vec![]);
            }

            if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("\\x")) {
                if hex_str.len() % 2 == 0 && hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return CborValue::Bytes(hex::decode(hex_str).expect("Invalid hex string"));
                }
            }

            CborValue::Text(s)
        }
        JsonValue::Object(obj) => {
            let transformed_obj = obj
                .into_iter()
                .map(|(k, v)| (
                    k.parse::<i64>()
                        .map_or_else(|_| CborValue::Text(k), |num| CborValue::Integer(num as i128)),
                    transform_json(v)
                ))
                .collect();
            CborValue::Map(transformed_obj)
        }
        JsonValue::Array(arr) => CborValue::Array(arr.into_iter().map(transform_json).collect()),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                CborValue::Integer(i as i128)
            } else {
                CborValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        JsonValue::Bool(b) => CborValue::Bool(b),
        JsonValue::Null => CborValue::Null,
    }
}

pub fn cbor_to_json(value: CborValue, with_byte_arrays: bool) -> JsonValue {
    match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(b) => JsonValue::Bool(b),
        CborValue::Integer(i) => JsonValue::Number(serde_json::Number::from(i as i64)),
        CborValue::Float(f) => {
            JsonValue::Number(serde_json::Number::from_f64(f).expect("Invalid float value"))
        }
        CborValue::Bytes(b) => {
            if let Ok(nested_cbor) = serde_cbor::from_slice::<CborValue>(&b) {
                return cbor_to_json(nested_cbor, with_byte_arrays);
            }
            let encoded = hex::encode(b);
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", encoded)
            } else {
                encoded
            })
        }
        CborValue::Text(t) => {
            JsonValue::String(t.replace('\u{0}', ""))
        }
        CborValue::Array(arr) => JsonValue::Array(
            arr.into_iter()
                .map(|v| cbor_to_json(v, with_byte_arrays))
                .collect(),
        ),
        CborValue::Map(map) => {
            let mut ordered_map = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    CborValue::Text(t) => t.replace('\u{0}', ""),
                    CborValue::Bytes(b) => {
                        let encoded = hex::encode(b);
                        if with_byte_arrays {
                            format!("\\x{}", encoded)
                        } else {
                            encoded
                        }
                    }
                    CborValue::Integer(i) => i.to_string(),
                    _ => {
                        let encoded = hex::encode(serde_cbor::to_vec(&k).unwrap());
                        if with_byte_arrays {
                            format!("\\x{}", encoded)
                        } else {
                            encoded
                        }
                    }
                };
                ordered_map.insert(key, cbor_to_json(v, with_byte_arrays));
            }
            JsonValue::Object(ordered_map)
        }
        CborValue::Tag(tag, boxed) => {
            let encoded = hex::encode(serde_cbor::to_vec(&CborValue::Tag(tag, boxed)).unwrap());
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", encoded)
            } else {
                encoded
            })
        }
        _ => unreachable!(),
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
