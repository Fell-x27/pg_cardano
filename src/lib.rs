use bech32::Bech32;
use bech32::Hrp;
use bs58;
use pgrx::prelude::*;
use bech32::{self, encode, decode};
use serde::{Serialize, Deserialize};
use serde_cbor::{to_vec, from_slice};
use serde_json::Value;
use pgrx::JsonB;
use hex;
use blake2::{Blake2b, Blake2bVar, Digest, };
use blake2::digest::{VariableOutput, Update};

::pgrx::pg_module_magic!();

//bech32 +
//base58 +
//cbor +
//blake2b +
//ed25519


//Base58
#[pg_extern]
fn base58_encode(input: &[u8]) -> String {
    bs58::encode(input).into_string()
}

#[pg_extern]
fn base58_decode(input: &str) -> Vec<u8> {
    bs58::decode(input)
        .into_vec()
        .expect("Failed to decode Base58 string")
}

// Bech32 encode
#[pg_extern]
fn bech32_encode(hrp: &str, input: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("Failed to parse HRP");
    encode::<Bech32>(hrp, input).expect("Failed to encode Bech32")
}

// Bech32 decode
#[pg_extern]
fn bech32_decode_prefix(bech32_str: &str) -> String {
    let (hrp, _) = decode(bech32_str).expect("Failed to decode Bech32 string");
    hrp.to_string()
}

#[pg_extern]
fn bech32_decode_data(bech32_str: &str) -> Vec<u8> {
    let (_, data) = decode(bech32_str).expect("Failed to decode Bech32 string");
    data
}

//Cbor
#[pg_extern]
fn jsonb_to_cbor(input: JsonB) -> Vec<u8> {
    let value: Value = serde_json::from_value(input.0).expect("Failed to parse JsonB");
    to_vec(&value).expect("Failed to encode CBOR")
}

#[pg_extern]
fn cbor_to_jsonb(cbor_bytes: &[u8]) -> JsonB {
    let value: Value = from_slice(cbor_bytes).expect("Failed to decode CBOR");
    JsonB(serde_json::to_value(&value).expect("Failed to convert to JsonB"))
}

// B2B
#[pg_extern]
fn blake2b(input: &[u8], output_length: i32) -> Vec<u8> {
    let output_length = output_length as usize;
    if !(1..=64).contains(&output_length) {
        panic!("Output length must be between 1 and 64 bytes");
    }
    let mut hasher = Blake2bVar::new(output_length).expect("Failed to create Blake2bVar");
    hasher.update(input);

    let mut output = vec![0u8; output_length];
    hasher.finalize_variable(&mut output).expect("Failed to finalize hash");

    output
}
///////////////////

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_base58_enc() {
        assert_eq!("3Z6ioYHE3x", crate::base58_encode(b"Cardano"));
    }

    #[pg_test]
    fn test_base58_dec() {
        assert_eq!(b"Cardano".to_vec(), crate::base58_decode("3Z6ioYHE3x"));
    }

    #[pg_test]
    fn test_bech32_enc() {
        assert_eq!("ada1d9ejqctdv9axjmn8dypl4d", crate::bech32_encode("ada", b"is amazing"));
    }

    #[pg_test]
    fn test_bech32_prefix_dec() {
        assert_eq!("ada", crate::bech32_decode_prefix("ada1d9ejqctdv9axjmn8dypl4d"));
    }

    #[pg_test]
    fn test_bech32_data_dec() {
        assert_eq!(b"is amazing".to_vec(), crate::bech32_decode_data("ada1d9ejqctdv9axjmn8dypl4d"));
    }

    #[pg_test]
    fn test_cbor_enc() {
        let original_json = pgrx::JsonB(serde_json::json!({
          "ada": "is amazing!",
          "features": [
            "science",
            "approach"
          ],
          "version": 1.0
        }));

        let cbor_bytes = crate::jsonb_to_cbor(original_json);
        let sample = hex::decode("a3636164616b697320616d617a696e67216866656174757265738267736369656e636568617070726f6163686776657273696f6ef93c00").expect("Failed to decode hex");
        assert_eq!(sample, cbor_bytes);
    }

    #[pg_test]
    fn test_cbor_dec() {
        let original_json = pgrx::JsonB(serde_json::json!({
          "ada": "is amazing!",
          "features": [
            "science",
            "approach"
          ],
          "version": 1.0
        }));

        let cbor_bytes = hex::decode("a3636164616b697320616d617a696e67216866656174757265738267736369656e636568617070726f6163686776657273696f6ef93c00").expect("Failed to decode hex");;
        let sample = crate::cbor_to_jsonb(&cbor_bytes);

        assert_eq!(
            serde_json::to_string(&sample.0).expect("Failed to serialize sample"),
            serde_json::to_string(&original_json.0).expect("Failed to serialize original_json")
        );
    }

    #[pg_test]
    fn test_blake2b_hash() {
        let data = b"Cardano is amazing!";
        let expected_hash = hex::decode("2244d5c9699fa93b0a8ed3ae952f88c9b872177e8a8ffcd8126a0d69e6806545").expect("Failed to decode hex");

        let result_hash = crate::blake2b(data, 32);

        assert_eq!(expected_hash, result_hash);
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
