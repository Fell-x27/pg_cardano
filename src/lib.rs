use pgrx::prelude::*;
use serde_cbor::{to_vec, from_slice};
use serde_json::Value;
use pgrx::JsonB;

use bech32::{self, Bech32, Hrp, encode, decode};
use bs58;

use blake2::{Blake2bVar};
use blake2::digest::{VariableOutput, Update};

use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};


pg_module_magic!();

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

    // Bech32
    #[pg_extern]
    pub(crate) fn bech32_encode(hrp: &str, input: &[u8]) -> String {
        let hrp = Hrp::parse(hrp).expect("Failed to parse HRP");
        encode::<Bech32>(hrp, input).expect("Failed to encode Bech32")
    }

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

    // Blake2B
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
    pub(crate) fn ed25519_sign_message(secret_key_bytes: &[u8], message: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&secret_key_bytes.try_into().expect("Invalid secret key length"));
        let signature: Signature = signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    // ed25519 ver
    #[pg_extern]
    pub(crate) fn ed25519_verify_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length"))
            .expect("Invalid public key");
        let signature = Signature::try_from(&signature_bytes[..]).expect("Invalid signature");
        verifying_key.verify(message, &signature).is_ok()
    }

    //High-level tools
    pub mod tools {
        use super::*;

        // dRep view_id builders
        pub(crate) fn drep_id_encode_cip105(raw_id_bytes: &[u8], is_script: bool) -> String {
            let hrp = if is_script { "drep_script" } else { "drep" };
            bech32_encode(hrp, raw_id_bytes)
        }

        pub(crate) fn drep_id_encode_cip129(raw_id_bytes: &[u8], is_script: bool) -> String {
            //add 22[0010 0010] for keyhash;
            //add 23[0010 0011] for script;
            let byte_prefix = if is_script { 0x23 } else { 0x22 };
            let hrp = "drep";

            let mut input_with_prefix = Vec::with_capacity(1 + raw_id_bytes.len());  // Выделяем место для одного байта + исходные байты
            input_with_prefix.push(byte_prefix);
            input_with_prefix.extend_from_slice(raw_id_bytes);

            bech32_encode(hrp, &input_with_prefix)
        }

        // Shelley Addr builders
        pub(crate) fn build_shelley_base_address(payment_cred: &[u8], stake_cred: &[u8], addr_type: u8, network_id: u8) -> String {
            if addr_type > 5  {
                panic!("Invalid addr_type: {}. Expected value <= 5.", addr_type);
            }

            if network_id > 1  {
                panic!("Invalid network_id: {}. Expected value 0 or 1.", network_id);
            }

            if payment_cred.len() != 28 {
                panic!("Invalid payment_cred length: {}. Expected 28 bytes.", payment_cred.len());
            }

            if stake_cred.len() != 28 {
                panic!("Invalid stake_cred length: {}. Expected 28 bytes.", stake_cred.len());
            }

            let mut address_bytes = Vec::with_capacity(1 + payment_cred.len() + stake_cred.len());
            let combined_byte = (addr_type << 4) | (network_id & 0x0F);
            address_bytes.push(combined_byte);
            address_bytes.extend_from_slice(payment_cred);
            address_bytes.extend_from_slice(stake_cred);
            let addr_prefix = if network_id == 0 { "addr_test" } else { "addr" };
            bech32_encode(addr_prefix, &address_bytes)
        }

        pub(crate) fn build_shelley_enterprise_address(payment_cred: &[u8], addr_type: u8, network_id: u8) -> String {
            if addr_type < 6 || addr_type > 7 {
                panic!("Invalid addr_type: {}. Expected value between 6 and 7.", addr_type);
            }

            if network_id > 1 {
                panic!("Invalid network_id: {}. Expected value 0 or 1.", addr_type);
            }

            if payment_cred.len() != 28 {
                panic!("Invalid payment_cred length: {}. Expected 28 bytes.", payment_cred.len());
            }

            let mut address_bytes = Vec::with_capacity(1 + payment_cred.len());
            let combined_byte = (addr_type << 4) | (network_id & 0x0F);
            address_bytes.push(combined_byte);
            address_bytes.extend_from_slice(payment_cred);
            let addr_prefix = if network_id == 0 { "addr_test" } else { "addr" };
            bech32_encode(addr_prefix, &address_bytes)
        }

        pub(crate) fn build_shelley_reward_address(stake_cred: &[u8], addr_type: u8, network_id: u8) -> String {
            if addr_type < 14 || addr_type > 15 {
                panic!("Invalid addr_type: {}. Expected value between 14 and 15.", addr_type);
            }

            if network_id > 1 {
                panic!("Invalid network_id: {}. Expected value 0 or 1.", addr_type);
            }

            if stake_cred.len() != 28 {
                panic!("Invalid stake_cred length: {}. Expected 28 bytes.", stake_cred.len());
            }

            let mut address_bytes = Vec::with_capacity(1 + stake_cred.len());
            let combined_byte = (addr_type << 4) | (network_id & 0x0F);
            address_bytes.push(combined_byte);
            address_bytes.extend_from_slice(stake_cred);
            let addr_prefix = if network_id == 0 { "stake_test" } else { "stake" };
            bech32_encode(addr_prefix, &address_bytes)
        }

        // Shelley Addr extractors
        pub(crate) fn extract_shelley_addr_payment_cred(shelley_address_bech32: &str) -> Vec<u8> {
            let raw_address = bech32_decode_data(&shelley_address_bech32);

            if raw_address.len() < 29 {
                panic!("Invalid address length: {}. Expected at least 29 bytes.", raw_address.len());
            }

            let payment_cred = raw_address[1..29].to_vec();
            payment_cred
        }
        pub(crate) fn extract_base_addr_stake_cred(base_address_bech32: &str) -> Vec<u8> {
            let raw_address = bech32_decode_data(&base_address_bech32);

            if raw_address.len() != 57 {
                panic!("Invalid address length: {} . Expected 57 bytes.", raw_address.len());
            }

            let stake_cred = raw_address[29..57].to_vec();
            stake_cred
        }

        pub(crate) fn extract_reward_addr_stake_cred(reward_address_bech32: &str) -> Vec<u8> {
            extract_shelley_addr_payment_cred(&reward_address_bech32)
        }

        // Shelley Addr type detector
        pub(crate) fn get_addr_type(base_address_bech32: &str) -> String {
            let raw_address = bech32_decode_data(&base_address_bech32);
            let addr_type_byte = raw_address[0] >> 4;

            let addr_type = match addr_type_byte {
                0b0000 => "PMT_KEY:STK_KEY",
                0b0001 => "PMT_SCRIPT:STK_KEY",
                0b0010 => "PMT_KEY:STK_SCRIPT",
                0b0011 => "PMT_SCRIPT:STK_SCRIPT",
                0b0100 => "PMT_KEY:POINTER",
                0b0101 => "PMT_SCRIPT:POINTER",
                0b0110 => "PMT_KEY:NONE",
                0b0111 => "PMT_SCRIPT:NONE",
                0b1110 => "STK_KEY",
                0b1111 => "STK_SCRIPT",
                _ => "UNKNOWN",
            };
            addr_type.to_string()
        }
    }
}

////////////////////// TESTS ///////////////////////////

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::pg_sys::netent;
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
        let result = crate::cardano::base58_decode(input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_bech32_enc() {
        let hrp = "ada";
        let input = b"is amazing";
        let expected_output = "ada1d9ejqctdv9axjmn8dypl4d";
        let result = crate::cardano::bech32_encode(hrp, input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_bech32_prefix_dec() {
        let input = "ada1d9ejqctdv9axjmn8dypl4d";
        let expected_output = "ada";
        let result = crate::cardano::bech32_decode_prefix(input);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_bech32_data_dec() {
        let input = "ada1d9ejqctdv9axjmn8dypl4d";
        let expected_output = b"is amazing".to_vec();
        let result = crate::cardano::bech32_decode_data(input);

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
        let result = crate::cardano::jsonb_to_cbor(original_json);

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
        let result = crate::cardano::cbor_to_jsonb(&cbor_bytes);

        let expected_output = serde_json::to_string(&original_json.0).expect("Failed to serialize original_json");
        let result_str = serde_json::to_string(&result.0).expect("Failed to serialize result");

        assert_eq!(expected_output, result_str);
    }

    #[pg_test]
    fn test_blake2b_hash() {
        let data = b"Cardano is amazing!";
        let expected_output = hex::decode("2244d5c9699fa93b0a8ed3ae952f88c9b872177e8a8ffcd8126a0d69e6806545")
            .expect("Failed to decode hex");
        let result = crate::cardano::blake2b(data, 32);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_ed25519_sign() {
        let message = b"Cardano is amazing!";
        let secret_key = hex::decode("43D68AECFA7B492F648CE90133D10A97E4300FB3C08B5D843F05BDA7EF53B3E3")
            .expect("Failed to decode hex");
        let expected_signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");
        let result_signature = crate::cardano::ed25519_sign_message(&secret_key, message);

        assert_eq!(result_signature, expected_signature);
    }

    #[pg_test]
    fn test_ed25519_verify() {
        let message = b"Cardano is amazing!";
        let public_key = hex::decode("432753BDFD91EA3E2DA1E3A0784D090D7088E2B176AE7C11DFA2D75E2A6C12FB")
            .expect("Failed to decode hex");
        let signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");

        let is_valid = crate::cardano::ed25519_verify_signature(&public_key, message, &signature);

        assert!(is_valid);
    }

    #[pg_test]
    fn test_drep_id_pubkey_encode_cip105() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155").expect("Failed to decode hex");
        let pubkey_view_id = crate::cardano::tools::drep_id_encode_cip105(&drep_raw_id, false);
        let pubkey_view_id_expected = "drep19qg34ctllr7lh48nnj4akfc978qzqzuwzkgsdu6r3zc42e5y854";

        assert_eq!(pubkey_view_id_expected, pubkey_view_id);
    }

    #[pg_test]
    fn test_drep_id_script_encode_cip105() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155").expect("Failed to decode hex");
        let script_view_id = crate::cardano::tools::drep_id_encode_cip105(&drep_raw_id, true);
        let script_view_id_expected = "drep_script19qg34ctllr7lh48nnj4akfc978qzqzuwzkgsdu6r3zc42kke0g5";

        assert_eq!(script_view_id_expected, script_view_id);
    }

    #[pg_test]
    fn test_drep_id_pubkey_encode_cip129() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155").expect("Failed to decode hex");
        let pubkey_view_id = crate::cardano::tools::drep_id_encode_cip129(&drep_raw_id, false);
        let pubkey_view_id_expected = "drep1yg5pzxhp0lu0m7757ww2hke8qhcuqgqt3c2ezphngwytz4gjr6yge";

        assert_eq!(pubkey_view_id_expected, pubkey_view_id);
    }

    #[pg_test]
    fn test_drep_id_script_encode_cip129() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155").expect("Failed to decode hex");
        let script_view_id = crate::cardano::tools::drep_id_encode_cip129(&drep_raw_id, true);
        let script_view_id_expected = "drep1yv5pzxhp0lu0m7757ww2hke8qhcuqgqt3c2ezphngwytz4gj324g7";

        assert_eq!(script_view_id_expected, script_view_id);
    }

    #[pg_test]
    fn test_build_shelley_base_address() {
        let p_cred = hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626").expect("Failed to decode hex");
        let s_cred = hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef").expect("Failed to decode hex");
        let addr_type = 0;
        let network_id = 0;
        let base_address = crate::cardano::tools::build_shelley_base_address(&p_cred, &s_cred, addr_type, network_id);
        let expected_result = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";

        assert_eq!(base_address, expected_result);
    }

    #[pg_test]
    fn test_build_shelley_enterprise_address() {
        let p_cred = hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626").expect("Failed to decode hex");
        let addr_type = 6;
        let network_id = 0;
        let base_address = crate::cardano::tools::build_shelley_enterprise_address(&p_cred, addr_type, network_id);
        let expected_result = "addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn";

        assert_eq!(base_address, expected_result);
    }

    #[pg_test]
    fn test_build_shelley_reward_address() {
        let s_cred = hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef").expect("Failed to decode hex");
        let addr_type = 14;
        let network_id = 0;
        let base_address = crate::cardano::tools::build_shelley_reward_address(&s_cred, addr_type, network_id);
        let expected_result = "stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85";

        assert_eq!(base_address, expected_result);
    }

    #[pg_test]
    fn test_extract_shelley_base_address_payment_cred() {
        let base_address = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";
        let expected_result = hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626").expect("Failed to decode hex");
        let p_cred = crate::cardano::tools::extract_shelley_addr_payment_cred(&base_address);
        assert_eq!(p_cred, expected_result);
    }

    #[pg_test]
    fn test_extract_shelley_enterprise_address_payment_cred() {
        let enterprise_address = "addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn";
        let expected_result = hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626").expect("Failed to decode hex");
        let p_cred = crate::cardano::tools::extract_shelley_addr_payment_cred(&enterprise_address);
        assert_eq!(p_cred, expected_result);
    }

    #[pg_test]
    fn test_extract_base_address_stake_cred() {
        let base_address = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";
        let expected_result = hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef").expect("Failed to decode hex");
        let s_cred = crate::cardano::tools::extract_base_addr_stake_cred(&base_address);
        assert_eq!(s_cred, expected_result);
    }

    #[pg_test]
    fn test_extract_reward_address_stake_cred() {
        let reward_address = "stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85";
        let expected_result = hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef").expect("Failed to decode hex");
        let s_cred = crate::cardano::tools::extract_reward_addr_stake_cred(&reward_address);
        assert_eq!(s_cred, expected_result);
    }

    #[pg_test]
    fn test_get_addr_type() {
        let reward_address = "stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85";
        let reward_addr_type = crate::cardano::tools::get_addr_type(&reward_address);
        assert_eq!(reward_addr_type, "STK_KEY");

        let base_address = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";
        let base_addr_type = crate::cardano::tools::get_addr_type(&base_address);
        assert_eq!(base_addr_type, "PMT_KEY:STK_KEY");

        let enterprise_address = "addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn";
        let enterprise_addr_type = crate::cardano::tools::get_addr_type(&enterprise_address);
        assert_eq!(enterprise_addr_type, "PMT_KEY:NONE");
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
