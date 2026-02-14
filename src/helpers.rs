use ciborium::value::Value as CborValue;
use hex;
use serde_json::{json, Map as JsonMap, Number, Value as JsonValue};

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

fn unfold_nested_cbor(original: CborValue, aggressive: bool) -> CborValue {
    let mut value = original;

    loop {
        match &value {
            CborValue::Tag(24, boxed) => {
                if let CborValue::Bytes(b) = boxed.as_ref() {
                    if let Some(decoded) = try_decode_bytes(b) {
                        value = decoded;
                        continue;
                    }
                }
                break value;
            }

            CborValue::Bytes(b) => {
                if let Some(decoded) = try_decode_bytes(b) {
                    if aggressive {
                        value = decoded;
                        continue;
                    } else {
                        match decoded {
                            CborValue::Map(_)
                            | CborValue::Array(_)
                            | CborValue::Tag(_, _)
                            | CborValue::Text(_) => {
                                value = decoded;
                                continue;
                            }
                            _ => {}
                        }
                    }
                }
                break value;
            }

            _ => break value,
        }
    }
}

fn try_decode_bytes(bytes: &[u8]) -> Option<CborValue> {
    let mut cursor = std::io::Cursor::new(bytes);
    if let Ok(parsed) = ciborium::de::from_reader::<CborValue, _>(&mut cursor) {
        if cursor.position() as usize == bytes.len() {
            Some(parsed)
        } else {
            None
        }
    } else {
        None
    }
}

pub fn cbor_to_json(value: &CborValue, with_byte_arrays: bool,  aggressive: bool) -> JsonValue {
    let value = unfold_nested_cbor(value.clone(), aggressive);

    match value {
        CborValue::Null => JsonValue::Null,

        CborValue::Bool(b) => JsonValue::Bool(b),

        CborValue::Integer(i) => {
            let n: i128 = i.into();
            match i64::try_from(n) {
                Ok(as_i64) => JsonValue::Number(Number::from(as_i64)),
                Err(_) => JsonValue::String(n.to_string()),
            }
        }

        CborValue::Float(f) => {
            JsonValue::Number(Number::from_f64(f).expect("Invalid float"))
        }

        CborValue::Bytes(b) => {
            let hex_str = hex::encode(b);
            JsonValue::String(if with_byte_arrays {
                format!("\\x{}", hex_str)
            } else {
                hex_str
            })
        }

        CborValue::Text(t) => JsonValue::String(t.replace('\u{0}', "")),

        CborValue::Array(arr) => {
            let items = arr
                .into_iter()
                .map(|v| {
                    let v = unfold_nested_cbor(v, aggressive);
                    cbor_to_json(&v, with_byte_arrays, aggressive)
                })
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
                        let i128_val: i128 = i.into();
                        i128_val.to_string()
                    }
                    other => {
                        let mut buf = Vec::new();
                        ciborium::ser::into_writer(&other, &mut buf)
                            .expect("Failed to serialize CBOR map key");
                        let hex_str = hex::encode(buf);
                        if with_byte_arrays {
                            format!("\\x{}", hex_str)
                        } else {
                            hex_str
                        }
                    }
                };

                let v = unfold_nested_cbor(v, aggressive);
                result.insert(key, cbor_to_json(&v, with_byte_arrays, aggressive));
            }

            JsonValue::Object(result)
        }

        CborValue::Tag(tag, boxed) => {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&CborValue::Tag(tag, boxed.clone()), &mut buf)
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

pub fn cbor_to_json_ext(value: &ciborium::value::Value) -> serde_json::Value {
    fn content_object(type_: &str, data: JsonValue, tag: Option<u64>) -> JsonValue {
        let mut obj = JsonMap::new();
        if let Some(tag_val) = tag {
            obj.insert("tag".to_string(), JsonValue::Number(tag_val.into()));
        }
        obj.insert("type".to_string(), JsonValue::String(type_.to_string()));
        obj.insert("value".to_string(), data);

        JsonValue::Object(obj)
    }

    fn to_content(cbor: &CborValue, tag: Option<u64>) -> JsonValue {
        match cbor {
            CborValue::Tag(t, inner) => to_content(inner, Some(*t)),

            CborValue::Null => content_object("null", JsonValue::Null, tag),

            CborValue::Bool(b) => content_object("bool", JsonValue::Bool(*b), tag),

            CborValue::Integer(i) => {
                let val = i128::from(i.clone());
                content_object("int", JsonValue::String(val.to_string()), tag)
            }

            CborValue::Float(f) => {
                content_object("float", JsonValue::String(f.to_string()), tag)
            }

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

                let mut obj = JsonMap::new();
                obj.insert("type".to_string(), JsonValue::String("string".to_string()));
                obj.insert("value".to_string(), JsonValue::String(clean));
                if let Some(tag_val) = tag {
                    obj.insert("tag".to_string(), JsonValue::Number(tag_val.into()));
                }
                if !nulls.is_empty() {
                    obj.insert(
                        "nulls".to_string(),
                        JsonValue::Array(
                            nulls.into_iter().map(|i| JsonValue::Number(i.into())).collect(),
                        ),
                    );
                }

                JsonValue::Object(obj)
            }

            CborValue::Bytes(b) => {
                content_object("bytes", JsonValue::String(hex::encode(b)), tag)
            }

            CborValue::Array(arr) => {
                let elements = arr.iter().map(|v| to_content(v, None)).collect::<Vec<_>>();
                content_object("array", JsonValue::Array(elements), tag)
            }

            CborValue::Map(entries) => {
                let pairs = entries
                    .iter()
                    .map(|(k, v)| {
                        let key = to_content(k, None);
                        let value = to_content(v, None);
                        json!({
                            "key": key,
                            "val": value
                        })
                    })
                    .collect::<Vec<_>>();
                content_object("map", JsonValue::Array(pairs), tag)
            }

            _ => content_object("unsupported", JsonValue::Null, tag),
        }
    }

    to_content(value, None)
}

pub fn json_to_cbor_ext(json: &serde_json::Value) -> ciborium::value::Value {
    fn parse_content(content: &JsonValue) -> CborValue {
        let obj = match content.as_object() {
            Some(map) => map,
            None => return CborValue::Null,
        };

        let type_str = obj.get("type").and_then(|v| v.as_str()).unwrap_or("null");
        let tag = obj.get("tag").and_then(|v| v.as_u64());
        let data = obj.get("value");

        let base = match type_str {
            "null" => CborValue::Null,

            "bool" => {
                let b = data.and_then(|v| v.as_bool()).unwrap_or(false);
                CborValue::Bool(b)
            }

            "int" => {
                let i = data
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                CborValue::Integer(i.into())
            }

            "float" => {
                let f = data
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                CborValue::Float(f)
            }

            "string" => {
                let s = data.and_then(|v| v.as_str()).unwrap_or("");
                let nulls = obj.get("nulls").and_then(|n| {
                    n.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|x| x as usize))
                            .collect::<Vec<_>>()
                    })
                });
                let restored = if let Some(null_positions) = nulls {
                    let mut chars: Vec<char> = s.chars().collect();
                    let mut offset = 0;
                    for &pos in &null_positions {
                        let insert_pos = pos + offset;
                        if insert_pos <= chars.len() {
                            chars.insert(insert_pos, '\u{0000}');
                            offset += 1;
                        }
                    }
                    chars.into_iter().collect()
                } else {
                    s.to_string()
                };
                CborValue::Text(restored)
            }

            "bytes" => {
                let hex_str = data.and_then(|v| v.as_str()).unwrap_or("");
                let bytes = hex::decode(hex_str).unwrap_or_default();
                CborValue::Bytes(bytes)
            }

            "array" => {
                let items = match data.and_then(|v| v.as_array()) {
                    Some(arr) => arr.iter().map(parse_content).collect(),
                    None => Vec::new(),
                };
                CborValue::Array(items)
            }

            "map" => {
                let pairs = match data.and_then(|v| v.as_array()) {
                    Some(arr) => arr
                        .iter()
                        .filter_map(|pair| {
                            let key = pair.get("key")?;
                            let value = pair.get("val")?;
                            Some((parse_content(key), parse_content(value)))
                        })
                        .collect(),
                    None => Vec::new(),
                };
                CborValue::Map(pairs)
            }

            _ => CborValue::Null,
        };

        match tag {
            Some(t) => CborValue::Tag(t, Box::new(base)),
            None => base,
        }
    }

    parse_content(json)
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
