mod tests;

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
