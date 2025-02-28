use hex;
use indexmap::IndexMap;
use serde_cbor::{self, Value as CborValue, de::Deserializer};
use serde_json::{Value as JsonValue};
use serde::Deserialize;

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

pub fn transform_json_new(value: JsonValue) -> CborValue {
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
                CborValue::Float(n.as_f64().unwrap_or(0.0)) // Убрали unwrap_or_default()
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
                cbor_to_json(nested_cbor, with_byte_arrays)
            } else {
                let encoded = hex::encode(b);
                JsonValue::String(if with_byte_arrays {
                    format!("\\x{}", encoded)
                } else {
                    encoded
                })
            }
        }
        CborValue::Text(t) => {
            let sanitized_text: String = t.chars().filter(|&c| c != '\u{0}').collect();
            JsonValue::String(sanitized_text)
        }
        CborValue::Array(arr) => JsonValue::Array(
            arr.into_iter()
                .map(|v| cbor_to_json(v, with_byte_arrays))
                .collect(),
        ),
        CborValue::Map(map) => {
            let mut ordered_map = IndexMap::new();
            for (k, v) in map {
                let key = match k {
                    CborValue::Text(t) => t.chars().filter(|&c| c != '\u{0}').collect::<String>(),
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
            eprintln!(
                "Ordered JSON object: {:?}",
                ordered_map.keys().collect::<Vec<_>>()
            );
            JsonValue::Object(serde_json::Map::from_iter(ordered_map.into_iter()))
        }
        _ => {
            let encoded = hex::encode(serde_cbor::to_vec(&value).unwrap());
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", encoded)
            } else {
                encoded
            })
        }
    }
}

pub fn cbor_to_json_new(value: CborValue, with_byte_arrays: bool) -> JsonValue {
    match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(b) => JsonValue::Bool(b),
        CborValue::Integer(i) => JsonValue::Number(serde_json::Number::from(i as i64)),
        CborValue::Float(f) => {
            JsonValue::Number(serde_json::Number::from_f64(f).expect("Invalid float value"))
        }
        CborValue::Bytes(b) => {
            // Если байты содержат CBOR, попробуем десериализовать их
            if let Ok(nested_cbor) = serde_cbor::from_slice::<CborValue>(&b) {
                return cbor_to_json(nested_cbor, with_byte_arrays);
            }
            // Иначе представляем как hex
            let encoded = hex::encode(b);
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", encoded)
            } else {
                encoded
            })
        }
        CborValue::Text(t) => {
            // Оптимизированное удаление \u{0}
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
            // Теги сохраняем как HEX-код CBOR
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

// pub fn cbor_to_json_new(data: &[u8], with_byte_arrays: bool) -> String {
//     let mut deserializer = Deserializer::from_slice(data);
//     let mut result = String::new();
//     result.push('[');
//     let mut first_elem = true;
//
//     while let Ok(val) = CborValue::deserialize(&mut deserializer) {
//         if !first_elem {
//             result.push(',');
//         } else {
//             first_elem = false;
//         }
//         append_value_json(&val, &mut result, with_byte_arrays);
//     }
//
//     result.push(']');
//     result
// }
//
//
// fn append_value_json(value: &CborValue, out: &mut String, with_byte_arrays: bool) {
//     // Lookup table for hex encoding
//     const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
//     match value {
//         CborValue::Null => out.push_str("null"),
//         CborValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
//         CborValue::Integer(i) => out.push_str(&i.to_string()),
//         CborValue::Float(f) => {
//             let num = serde_json::Number::from_f64(*f).expect("Invalid float value");
//             out.push_str(&num.to_string());
//         }
//         CborValue::Bytes(bytes) => {
//             out.push('"');
//             if with_byte_arrays {
//                 out.push_str("\\x");
//             } else {
//                 out.push_str("0x");
//             }
//             out.reserve(bytes.len() * 2);
//             for &byte in bytes {
//                 out.push(HEX_CHARS[(byte >> 4) as usize] as char);
//                 out.push(HEX_CHARS[(byte & 0xF) as usize] as char);
//             }
//             out.push('"');
//         }
//         CborValue::Text(s) => {
//             out.push('"');
//             out.push_str(&s.replace('\u{0}', ""));
//             out.push('"');
//         }
//         CborValue::Array(arr) => {
//             out.push('[');
//             let mut first = true;
//             for element in arr {
//                 if !first {
//                     out.push(',');
//                 } else {
//                     first = false;
//                 }
//                 append_value_json(element, out, with_byte_arrays);
//             }
//             out.push(']');
//         }
//         CborValue::Map(map) => {
//             out.push('{');
//             let mut first = true;
//             for (k, v) in map {
//                 if !first {
//                     out.push(',');
//                 } else {
//                     first = false;
//                 }
//                 out.push('"');
//                 match k {
//                     CborValue::Text(key_str) => out.push_str(&key_str.replace('\u{0}', "")),
//                     CborValue::Integer(i) => out.push_str(&i.to_string()),
//                     CborValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
//                     CborValue::Null => out.push_str("null"),
//                     CborValue::Float(f) => {
//                         let num = serde_json::Number::from_f64(*f).expect("Invalid float value");
//                         out.push_str(&num.to_string());
//                     }
//                     CborValue::Bytes(bytes) => {
//                         if with_byte_arrays {
//                             out.push_str("\\x");
//                         } else {
//                             out.push_str("0x");
//                         }
//                         out.reserve(bytes.len() * 2);
//                         for &byte in bytes {
//                             out.push(HEX_CHARS[(byte >> 4) as usize] as char);
//                             out.push(HEX_CHARS[(byte & 0xF) as usize] as char);
//                         }
//                     }
//                     // For non-simple keys (arrays, maps, tags), encode the key as hex of its CBOR representation
//                     _ => {
//                         let raw = serde_cbor::to_vec(k).unwrap();
//                         if with_byte_arrays {
//                             out.push_str("\\x");
//                         } else {
//                             out.push_str("0x");
//                         }
//                         out.reserve(raw.len() * 2);
//                         for &byte in &raw {
//                             out.push(HEX_CHARS[(byte >> 4) as usize] as char);
//                             out.push(HEX_CHARS[(byte & 0xF) as usize] as char);
//                         }
//                     }
//                 }
//                 out.push_str("\":");
//                 append_value_json(v, out, with_byte_arrays);
//             }
//             out.push('}');
//         }
//         CborValue::Tag(tag, boxed) => {
//             let raw = serde_cbor::to_vec(&CborValue::Tag(*tag, boxed.clone())).unwrap();
//             out.push('"');
//             if with_byte_arrays {
//                 out.push_str("\\x");
//             } else {
//                 out.push_str("0x");
//             }
//             out.reserve(raw.len() * 2);
//             for &byte in &raw {
//                 out.push(HEX_CHARS[(byte >> 4) as usize] as char);
//                 out.push(HEX_CHARS[(byte & 0xF) as usize] as char);
//             }
//             out.push('"');
//         }
//         _ => unreachable!(),
//     }
// }

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
