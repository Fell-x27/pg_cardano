use serde_json::{Value as JsonValue, Map};
use serde_cbor::Value;
use hex;

pub fn is_valid_hex(s: &str) -> bool {
    s.len() > 2 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_digit(16))
}

pub fn transform_json(value: JsonValue) -> Value {
    match value {
        JsonValue::String(s) if is_valid_hex(&s) => {
            let bytes = hex::decode(&s[2..]).expect("Invalid hex string");
            Value::Bytes(bytes)
        }
        JsonValue::Object(obj) => {
            let transformed_obj = obj
                .into_iter()
                .map(|(k, v)| {
                    let key = if let Ok(num) = k.parse::<i64>() {
                        Value::Integer(num as i128)
                    } else {
                        Value::Text(k)
                    };
                    (key, transform_json(v))
                })
                .collect();
            Value::Map(transformed_obj)
        }
        JsonValue::Array(arr) => Value::Array(arr.into_iter().map(transform_json).collect()),
        JsonValue::String(s) => Value::Text(s),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i as i128)
            } else {
                Value::Float(n.as_f64().unwrap())
            }
        }
        JsonValue::Bool(b) => Value::Bool(b),
        JsonValue::Null => Value::Null,
    }
}

pub fn cbor_to_json(value: Value, detect_hex_fields: bool) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Bool(b) => JsonValue::Bool(b),
        Value::Integer(i) => JsonValue::Number(serde_json::Number::from(i as i64)),
        Value::Float(f) => {
            JsonValue::Number(serde_json::Number::from_f64(f)
                .expect("Invalid float value"))
        }
        Value::Bytes(b) => {
            if let Ok(nested_cbor) = serde_cbor::from_slice::<Value>(&b) {
                cbor_to_json(nested_cbor, detect_hex_fields)
            } else {
                let hex_str = hex::encode(b);
                let formatted = if detect_hex_fields {
                    format!("0x{}", hex_str)
                } else {
                    hex_str
                };
                JsonValue::String(formatted)
            }
        }
        Value::Text(t) => {
            let sanitized_text: String =
                t.chars().filter(|&c| c != '\u{0}').collect();
            JsonValue::String(sanitized_text)
        }
        Value::Array(arr) => {
            let json_array = arr
                .into_iter()
                .map(|item| cbor_to_json(item, detect_hex_fields))
                .collect();
            JsonValue::Array(json_array)
        }
        Value::Map(map) => {
            let mut json_map = Map::with_capacity(map.len());
            for (k, v) in map {
                let key = match k {
                    Value::Text(t) => t,
                    Value::Bytes(b) => {
                        let hex_str = hex::encode(b);
                        if detect_hex_fields {
                            format!("0x{}", hex_str)
                        } else {
                            hex_str
                        }
                    }
                    Value::Integer(i) => i.to_string(),
                    _ => {
                        let vec = serde_cbor::to_vec(&k).unwrap();
                        let hex_str = hex::encode(vec);
                        if detect_hex_fields {
                            format!("0x{}", hex_str)
                        } else {
                            hex_str
                        }
                    }
                };
                json_map.insert(key, cbor_to_json(v, detect_hex_fields));
            }
            JsonValue::Object(json_map)
        }
        _ => {
            let vec = serde_cbor::to_vec(&value).unwrap();
            let hex_str = hex::encode(vec);
            let formatted = if detect_hex_fields {
                format!("0x{}", hex_str)
            } else {
                hex_str
            };
            JsonValue::String(formatted)
        }
    }
}


pub fn helper_shelley_addr_extract_main_cred(bech32_decode_data: impl Fn(&str) -> Vec<u8>, addr_bech32: &str) -> Vec<u8> {
    let raw_address = bech32_decode_data(addr_bech32);
    if raw_address.len() < 29 {
        panic!(
            "Invalid address length: {}. Expected at least 29 bytes.",
            raw_address.len()
        );
    }
    raw_address[1..29].to_vec()
}

pub fn helper_shelley_addr_extract_additional_cred(bech32_decode_data: impl Fn(&str) -> Vec<u8>, addr_bech32: &str) -> Vec<u8> {
    let raw_address = bech32_decode_data(addr_bech32);
    if raw_address.len() != 57 {
        panic!(
            "Invalid address length: {}. Expected 57 bytes.",
            raw_address.len()
        );
    }
    raw_address[29..57].to_vec()
}
