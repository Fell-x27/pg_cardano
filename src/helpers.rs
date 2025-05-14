use ciborium::value::Value as CborValue;
use serde_json::{json, Map as JsonMap, Number, Value as JsonValue};
use hex;

pub fn json_to_cbor(value: &JsonValue) -> CborValue {
    match value {
        JsonValue::String(s) => {
            if s.is_empty() || matches!(s.as_str(), "\\x" | "0x") {
                return CborValue::Bytes(vec![]);
            }

            if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("\\x")) {
                if hex_str.len() % 2 == 0 && hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return CborValue::Bytes(hex::decode(hex_str).unwrap_or_default());
                }
            }

            CborValue::Text(s.clone())
        }

        JsonValue::Object(obj) => {
            let items = obj.iter().map(|(k, v)| {
                let key = k.parse::<i64>()
                    .map_or(CborValue::Text(k.clone()), |n| CborValue::Integer(n.into()));
                (key, json_to_cbor(v))
            }).collect();

            CborValue::Map(items)
        }

        JsonValue::Array(arr) => {
            CborValue::Array(arr.iter().map(json_to_cbor).collect())
        }

        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                CborValue::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                CborValue::Float(f)
            } else {
                CborValue::Float(0.0)
            }
        }

        JsonValue::Bool(b) => CborValue::Bool(*b),

        JsonValue::Null => CborValue::Null,
    }
}

pub fn cbor_to_json(value: CborValue, with_byte_arrays: bool) -> JsonValue {
    match value {
        CborValue::Null => JsonValue::Null,

        CborValue::Bool(b) => JsonValue::Bool(b),

        CborValue::Integer(i) => {
            let n: i128 = i.clone().into();

            match i64::try_from(n) {
                Ok(as_i64) => JsonValue::Number(serde_json::Number::from(as_i64)),
                Err(_) => JsonValue::String(n.to_string()),
            }
        }

        CborValue::Float(f) => {
            JsonValue::Number(Number::from_f64(f).expect("Invalid float"))
        }

        CborValue::Bytes(b) => {
            if let Ok(nested_any) = ciborium::de::from_reader::<CborValue, _>(b.as_slice()) {
                match &nested_any {
                    CborValue::Map(_)
                    |CborValue::Array(_)
                    | CborValue::Tag(_, _)
                    | CborValue::Text(_) => {
                        let nested = CborValue::from(nested_any);
                        return cbor_to_json(nested, with_byte_arrays);
                    }
                    _ => {}
                }
            }

            let hex_str = hex::encode(b);
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", hex_str)
            } else {
                hex_str
            })
        }

        CborValue::Text(t) => {
            JsonValue::String(t.replace('\u{0}', ""))
        }

        CborValue::Array(arr) => {
            let items = arr.into_iter()
                .map(|v| cbor_to_json(v, with_byte_arrays))
                .collect();
            JsonValue::Array(items)
        }

        CborValue::Map(map) => {
            let mut result = JsonMap::new();

            for (k, v) in map {
                let key = match k {
                    CborValue::Text(t) => t.replace('\u{0}', ""),
                    CborValue::Bytes(b) => {
                        let hex_str = hex::encode(b);
                        if with_byte_arrays {
                            format!("\\x{}", hex_str)
                        } else {
                            hex_str
                        }
                    }
                    CborValue::Integer(i) => {
                        let i128_val: i128 = i.clone().into();
                        i128_val.to_string()
                    },
                    other => {
                        let encoded = {
                            let mut buf = Vec::new();
                            ciborium::ser::into_writer(&other, &mut buf)
                                .expect("Failed to serialize CBOR map key");
                            buf
                        };
                        let hex_str = hex::encode(encoded);
                        if with_byte_arrays {
                            format!("\\x{}", hex_str)
                        } else {
                            hex_str
                        }
                    }
                };

                result.insert(key, cbor_to_json(v, with_byte_arrays));
            }

            JsonValue::Object(result)
        }

        CborValue::Tag(tag, boxed) => {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&CborValue::Tag(tag, boxed), &mut buf)
                .expect("Failed to serialize CBOR Tag");

            let hex_str = hex::encode(buf);
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", hex_str)
            } else {
                hex_str
            })
        }
        _ => panic!("Unknown CBOR value"),
    }
}

pub fn cbor_to_json_ext(value: &CborValue) -> JsonValue {
    fn to_node(cbor: &CborValue, tag: Option<u64>) -> JsonValue {
        match cbor {
            CborValue::Tag(tag_val, inner) => {
                let mut result = to_node(inner, None);

                if let JsonValue::Object(ref mut obj) = result {
                    obj.insert("tag".to_string(), JsonValue::Number((*tag_val).into()));
                }

                result
            },

            CborValue::Null => json!({
                "type": "null",
                "value": null,
                "tag": tag
            }),

            CborValue::Bool(b) => json!({
                "type": "bool",
                "value": b,
                "tag": tag
            }),

            CborValue::Integer(i) => {
                let int_val = i128::from(i.clone());
                json!({
                    "type": "int",
                    "value": int_val,
                    "tag": tag
                })
            }

            CborValue::Float(f) => json!({
                "type": "float",
                "value": f,
                "tag": tag
            }),

            CborValue::Text(t) => {
                let mut clean = String::new();
                let mut nulls = Vec::new();

                for (i, ch) in t.chars().enumerate() {
                    if ch == '\u{0000}' {
                        nulls.push(i);
                    } else {
                        clean.push(ch);
                    }
                }

                let mut base = json!({
                    "type": "string",
                    "value": clean,
                    "tag": tag
                });

                if !nulls.is_empty() {
                    base["nulls"] = json!(nulls);
                }

                base
            }

            CborValue::Bytes(b) => json!({
                "type": "bytes",
                "value": hex::encode(b),
                "tag": tag
            }),

            CborValue::Array(arr) => {
                let inner = arr.iter().map(|v| to_node(v, None)).collect::<Vec<_>>();
                json!({
                    "type": "array",
                    "value": inner,
                    "tag": tag
                })
            }

            CborValue::Map(entries) => {
                let mapped = entries
                    .iter()
                    .map(|(k, v)| {
                        json!({
                            "key": to_node(k, None),
                            "value": to_node(v, None)
                        })
                    })
                    .collect::<Vec<_>>();

                json!({
                    "type": "map",
                    "value": mapped,
                    "tag": tag
                })
            },

            _ => json!({
                "type": "unsupported",
                "value": null,
                "tag": tag
            }),
        }
    }

    to_node(value, None)
}

pub fn json_to_cbor_ext(json: &JsonValue) -> CborValue {
    fn restore_string_with_nulls(base: &str, nulls: Option<&Vec<usize>>) -> String {
        if let Some(null_positions) = nulls {
            let mut chars: Vec<char> = base.chars().collect();
            let mut offset = 0;
            for &pos in null_positions {
                let insert_pos = pos + offset;
                if insert_pos <= chars.len() {
                    chars.insert(insert_pos, '\u{0000}');
                    offset += 1;
                }
            }
            chars.into_iter().collect()
        } else {
            base.to_string()
        }
    }

    fn parse_node(json: &JsonValue) -> CborValue {
        let typ = json.get("type").and_then(|t| t.as_str());
        let tag_val = json.get("tag").and_then(|v| v.as_u64());

        let value = match typ {
            Some("null") => CborValue::Null,

            Some("bool") => {
                let b = json.get("value").and_then(|v| v.as_bool()).unwrap_or(false);
                CborValue::Bool(b)
            }

            Some("int") => {
                let n = json.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
                CborValue::Integer(n.into())
            }

            Some("float") => {
                let f = json.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                CborValue::Float(f)
            }

            Some("string") => {
                let base = json.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let nulls = json.get("nulls").and_then(|n| {
                    n.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|x| x as usize))
                            .collect::<Vec<_>>()
                    })
                });
                let restored = restore_string_with_nulls(base, nulls.as_ref());
                CborValue::Text(restored)
            }

            Some("bytes") => {
                let hex_str = json.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let bytes = hex::decode(hex_str).unwrap_or_default();
                CborValue::Bytes(bytes)
            }

            Some("array") => {
                let inner = match json.get("value").and_then(|v| v.as_array()) {
                    Some(items) => items.iter().map(parse_node).collect(),
                    None => Vec::new(),
                };
                CborValue::Array(inner)
            }

            Some("map") => {
                let mapped = match json.get("value").and_then(|v| v.as_array()) {
                    Some(entries) => entries.iter().filter_map(|entry| {
                        let k = entry.get("key")?;
                        let v = entry.get("value")?;
                        Some((parse_node(k), parse_node(v)))
                    }).collect(),
                    None => Vec::new(),
                };
                CborValue::Map(mapped)
            }

            _ => CborValue::Null,
        };


        match tag_val {
            Some(tag) => CborValue::Tag(tag, Box::new(value)),
            None => value,
        }
    }

    parse_node(json)
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
