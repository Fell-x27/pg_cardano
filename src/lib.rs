use bech32::Bech32;
use bech32::Hrp;
use bs58;
use pgrx::prelude::*;
use bech32::{self, encode, decode};
use serde_cbor::{to_vec, from_slice};
use serde_json::Value;
use pgrx::JsonB;
use blake2::{Blake2bVar};
use blake2::digest::{VariableOutput, Update};
use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};

::pgrx::pg_module_magic!();

//bech32 +
//base58 +
//cbor +
//blake2b +
//ed25519 +

mod cardano {
    use super::*;
    //Base58
    #[pg_extern]
    pub(crate) fn base58_encode(input: &[u8]) -> String {
        bs58::encode(input).into_string()
    }

    #[pg_extern]
    pub(crate) fn base58_decode(input: &str) -> Vec<u8> {
        bs58::decode(input)
            .into_vec()
            .expect("Failed to decode Base58 string")
    }

    // Bech32 encode
    #[pg_extern]
    pub(crate) fn bech32_encode(hrp: &str, input: &[u8]) -> String {
        let hrp = Hrp::parse(hrp).expect("Failed to parse HRP");
        encode::<Bech32>(hrp, input).expect("Failed to encode Bech32")
    }

    // Bech32 decode
    #[pg_extern]
    pub(crate) fn bech32_decode_prefix(bech32_str: &str) -> String {
        let (hrp, _) = decode(bech32_str).expect("Failed to decode Bech32 string");
        hrp.to_string()
    }

    #[pg_extern]
    pub(crate) fn bech32_decode_data(bech32_str: &str) -> Vec<u8> {
        let (_, data) = decode(bech32_str).expect("Failed to decode Bech32 string");
        data
    }

    //Cbor
    #[pg_extern]
    pub(crate) fn jsonb_to_cbor(input: JsonB) -> Vec<u8> {
        let value: Value = serde_json::from_value(input.0).expect("Failed to parse JsonB");
        to_vec(&value).expect("Failed to encode CBOR")
    }

    #[pg_extern]
    pub(crate) fn cbor_to_jsonb(cbor_bytes: &[u8]) -> JsonB {
        let value: Value = from_slice(cbor_bytes).expect("Failed to decode CBOR");
        JsonB(serde_json::to_value(&value).expect("Failed to convert to JsonB"))
    }

    // B2B
    #[pg_extern]
    pub(crate) fn blake2b(input: &[u8], output_length: i32) -> Vec<u8> {
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


    // ed25519 sign
    #[pg_extern]
    pub(crate) fn ed25519_sign_message(secret_key_bytes: Vec<u8>, message: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&secret_key_bytes.try_into().expect("Invalid secret key length"));
        let signature: Signature = signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    // ed25519 ver
    #[pg_extern]
    pub(crate) fn ed25519_verify_signature(public_key_bytes: Vec<u8>, message: &[u8], signature_bytes: Vec<u8>) -> bool {
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length"))
            .expect("Invalid public key");
        let signature = Signature::try_from(&signature_bytes[..]).expect("Invalid signature");
        verifying_key.verify(message, &signature).is_ok()
    }

    mod cardano {
        use super::*;
    }
}

////////////////////// TESTS ///////////////////////////

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_base58_enc() {
        let input = b"Cardano";
        let expected_output = "3Z6ioYHE3x";
        let result = crate::cardano::base58_encode(input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_base58_dec() {
        let input = "3Z6ioYHE3x";
        let expected_output = b"Cardano".to_vec();
        let result =crate::cardano::base58_decode(input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_bech32_enc() {
        let hrp = "ada";
        let input = b"is amazing";
        let expected_output = "ada1d9ejqctdv9axjmn8dypl4d";
        let result =crate::cardano::bech32_encode(hrp, input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_bech32_prefix_dec() {
        let input = "ada1d9ejqctdv9axjmn8dypl4d";
        let expected_output = "ada";
        let result =crate::cardano::bech32_decode_prefix(input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_bech32_data_dec() {
        let input = "ada1d9ejqctdv9axjmn8dypl4d";
        let expected_output = b"is amazing".to_vec();
        let result =crate::cardano::bech32_decode_data(input);

        assert_eq!(expected_output, result);
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

        let expected_output = hex::decode("a3636164616b697320616d617a696e67216866656174757265738267736369656e636568617070726f6163686776657273696f6ef93c00")
            .expect("Failed to decode hex");
        let result =crate::cardano::jsonb_to_cbor(original_json);

        assert_eq!(expected_output, result);
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

        let cbor_bytes = hex::decode("a3636164616b697320616d617a696e67216866656174757265738267736369656e636568617070726f6163686776657273696f6ef93c00")
            .expect("Failed to decode hex");
        let result =crate::cardano::cbor_to_jsonb(&cbor_bytes);

        let expected_output = serde_json::to_string(&original_json.0).expect("Failed to serialize original_json");
        let result_str = serde_json::to_string(&result.0).expect("Failed to serialize result");

        assert_eq!(expected_output, result_str);
    }

    #[pg_test]
    fn test_blake2b_hash() {
        let data = b"Cardano is amazing!";
        let expected_output = hex::decode("2244d5c9699fa93b0a8ed3ae952f88c9b872177e8a8ffcd8126a0d69e6806545")
            .expect("Failed to decode hex");
        let result =crate::cardano::blake2b(data, 32);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_ed25519_sign() {
        let message = b"Cardano is amazing!";
        let secret_key = hex::decode("43D68AECFA7B492F648CE90133D10A97E4300FB3C08B5D843F05BDA7EF53B3E3")
            .expect("Failed to decode hex");
        let expected_signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");
        let result_signature =crate::cardano::ed25519_sign_message(secret_key.clone(), message);

        assert_eq!(result_signature, expected_signature);
    }

    #[pg_test]
    fn test_ed25519_verify() {
        let message = b"Cardano is amazing!";
        let public_key = hex::decode("432753BDFD91EA3E2DA1E3A0784D090D7088E2B176AE7C11DFA2D75E2A6C12FB")
            .expect("Failed to decode hex");
        let signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");

        let is_valid =crate::cardano::ed25519_verify_signature(public_key.clone(), message, signature.clone());

        assert!(is_valid);
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
