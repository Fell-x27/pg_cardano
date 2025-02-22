use pgrx::prelude::pg_schema;

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use hex;
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
    fn test_cbor_enc_jsonb() {
        let original_json = pgrx::JsonB(serde_json::json!({
            "version": 1.0,
            "features": [
                "science",
                "approach"
            ],
            "ada": "is amazing!"
        }));

        let expected_output = hex::decode("a3636164616b697320616d617a696e67216776657273696f6ef93c006866656174757265738267736369656e636568617070726f616368")
            .expect("Failed to decode hex");
        let result = crate::cardano::cbor_encode_jsonb(original_json);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_cbor_enc_jsonb_with_hex() {
        let original_json = pgrx::JsonB(serde_json::json!({
            "ada": "is amazing!",
            "version": 1.0,
            "features": [
                "science",
                "approach"
            ],
            "hex": "\\x6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb1"
        }));

        let expected_output = hex::decode("a4636164616b697320616d617a696e672163686578581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb16776657273696f6ef93c006866656174757265738267736369656e636568617070726f616368")
            .expect("Failed to decode hex");
        let result = crate::cardano::cbor_encode_jsonb(original_json);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_cbor_dec_to_jsonb_hes_as_hex() {
        let original_json = pgrx::JsonB(serde_json::json!({
            "ada": "is amazing!",
            "version": 1.0,
            "features": [
                "science",
                "approach"
            ],
            "hex": "\\x6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb1"
        }));

        let cbor_bytes = hex::decode("a4636164616b697320616d617a696e672163686578581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb16776657273696f6ef93c006866656174757265738267736369656e636568617070726f616368")
            .expect("Failed to decode hex");
        let result = crate::cardano::cbor_decode_jsonb_hex2bytea(&cbor_bytes);

        let expected_output =
            serde_json::to_string(&original_json.0).expect("Failed to serialize original_json");
        let result_str = serde_json::to_string(&result.0).expect("Failed to serialize result");

        assert_eq!(expected_output, result_str);
    }

    #[pg_test]
    fn test_cbor_dec_to_jsonb_hex_as_text() {
        let original_json = pgrx::JsonB(serde_json::json!({
            "ada": "is amazing!",
            "version": 1.0,
            "features": [
                "science",
                "approach"
            ],
            "hex": "6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb1"
        }));

        let cbor_bytes = hex::decode("a4636164616b697320616d617a696e672163686578581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb16776657273696f6ef93c006866656174757265738267736369656e636568617070726f616368")
            .expect("Failed to decode hex");
        let result = crate::cardano::cbor_decode_jsonb(&cbor_bytes);

        let expected_output =
            serde_json::to_string(&original_json.0).expect("Failed to serialize original_json");
        let result_str = serde_json::to_string(&result.0).expect("Failed to serialize result");

        assert_eq!(expected_output, result_str);
    }

    #[pg_test]
    fn test_cbor_dec_to_jsonb_with_null_symbol() {
        let cbor_bytes = hex::decode("a261610162620063636400")
            .expect("Failed to decode hex");

        let result = crate::cardano::cbor_decode_jsonb(&cbor_bytes);

        let result_str = serde_json::to_string(&result.0).expect("Failed to convert JsonB to string");

        assert_eq!("{\"a\":1,\"b\":\"cd\"}", result_str);
    }

    #[pg_test]
    fn test_blake2b_hash() {
        let data = b"Cardano is amazing!";
        let expected_output =
            hex::decode("2244d5c9699fa93b0a8ed3ae952f88c9b872177e8a8ffcd8126a0d69e6806545")
                .expect("Failed to decode hex");
        let result = crate::cardano::blake2b_hash(data, 32);

        assert_eq!(expected_output, result);
    }

    #[pg_test]
    fn test_ed25519_sign() {
        let message = b"Cardano is amazing!";
        let secret_key =
            hex::decode("43D68AECFA7B492F648CE90133D10A97E4300FB3C08B5D843F05BDA7EF53B3E3")
                .expect("Failed to decode hex");
        let expected_signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");
        let result_signature = crate::cardano::ed25519_sign_message(&secret_key, message);

        assert_eq!(result_signature, expected_signature);
    }

    #[pg_test]
    fn test_ed25519_verify() {
        let message = b"Cardano is amazing!";
        let public_key =
            hex::decode("432753BDFD91EA3E2DA1E3A0784D090D7088E2B176AE7C11DFA2D75E2A6C12FB")
                .expect("Failed to decode hex");
        let signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");

        let is_valid = crate::cardano::ed25519_verify_signature(&public_key, message, &signature);

        assert!(is_valid);
    }

    #[pg_test]
    fn test_ed25519_reject() {
        let message = b"Cardano is not amazing!";
        let public_key =
            hex::decode("432753BDFD91EA3E2DA1E3A0784D090D7088E2B176AE7C11DFA2D75E2A6C12FB")
                .expect("Failed to decode hex");
        let signature = hex::decode("74265F96E48EF1751F7C9CB3C5D376130664F6E00518FEFD10FB627112EF6DD29C424D335F236AECA9657B914FEC5DB9C0412E69858776B03A8FE476C0E7600F")
            .expect("Failed to decode hex");

        let is_valid = crate::cardano::ed25519_verify_signature(&public_key, message, &signature);

        assert!(!is_valid);
    }

    #[pg_test]
    fn test_drep_id_pubkey_encode_cip105() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155")
            .expect("Failed to decode hex");
        let pubkey_view_id = crate::cardano::tools_drep_id_encode_cip105(&drep_raw_id, false);
        let pubkey_view_id_expected =
            "drep_vkh19qg34ctllr7lh48nnj4akfc978qzqzuwzkgsdu6r3zc42lnl6a0";

        assert_eq!(pubkey_view_id_expected, pubkey_view_id);
    }

    #[pg_test]
    fn test_drep_id_script_encode_cip105() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155")
            .expect("Failed to decode hex");
        let script_view_id = crate::cardano::tools_drep_id_encode_cip105(&drep_raw_id, true);
        let script_view_id_expected =
            "drep_script19qg34ctllr7lh48nnj4akfc978qzqzuwzkgsdu6r3zc42kke0g5";

        assert_eq!(script_view_id_expected, script_view_id);
    }

    #[pg_test]
    fn test_drep_id_pubkey_encode_cip129() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155")
            .expect("Failed to decode hex");
        let pubkey_view_id = crate::cardano::tools_drep_id_encode_cip129(&drep_raw_id, false);
        let pubkey_view_id_expected = "drep1yg5pzxhp0lu0m7757ww2hke8qhcuqgqt3c2ezphngwytz4gjr6yge";

        assert_eq!(pubkey_view_id_expected, pubkey_view_id);
    }

    #[pg_test]
    fn test_drep_id_script_encode_cip129() {
        let drep_raw_id = hex::decode("28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155")
            .expect("Failed to decode hex");
        let script_view_id = crate::cardano::tools_drep_id_encode_cip129(&drep_raw_id, true);
        let script_view_id_expected = "drep1yv5pzxhp0lu0m7757ww2hke8qhcuqgqt3c2ezphngwytz4gj324g7";

        assert_eq!(script_view_id_expected, script_view_id);
    }

    #[pg_test]
    fn test_read_asset_name_utf8() {
        let utf8_bytes = "hello".as_bytes();
        let result = crate::cardano::tools_read_asset_name(utf8_bytes);
        assert_eq!(result, "hello");
    }

    #[pg_test]
    fn test_read_asset_name_non_utf8() {
        let non_utf8_bytes = hex::decode("deadbeef").expect("Failed to decode hex");
        let result = crate::cardano::tools_read_asset_name(&non_utf8_bytes);
        assert_eq!(result, "deadbeef");
    }

    #[pg_test]
    fn test_read_asset_name_empty() {
        let empty_bytes: &[u8] = &[];
        let result = crate::cardano::tools_read_asset_name(empty_bytes);
        assert_eq!(result, "");
    }

    #[pg_test]
    fn test_build_shelley_base_address() {
        let p_cred = hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626")
            .expect("Failed to decode hex");
        let s_cred = hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef")
            .expect("Failed to decode hex");
        let network_id = 0;
        let base_address =
            crate::cardano::tools_shelley_address_build(&p_cred, false, &s_cred, false, network_id);
        let expected_result = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";

        assert_eq!(base_address, expected_result);
    }

    #[pg_test]
    fn test_build_shelley_enterprise_address() {
        let p_cred = hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626")
            .expect("Failed to decode hex");
        let s_cred = hex::decode("").expect("Failed to decode hex");
        let network_id = 0;
        let base_address =
            crate::cardano::tools_shelley_address_build(&p_cred, false, &s_cred, false, network_id);
        let expected_result = "addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn";

        assert_eq!(base_address, expected_result);
    }

    #[pg_test]
    fn test_build_shelley_reward_address() {
        let p_cred = hex::decode("").expect("Failed to decode hex");
        let s_cred = hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef")
            .expect("Failed to decode hex");
        let network_id = 0;
        let base_address =
            crate::cardano::tools_shelley_address_build(&p_cred, false, &s_cred, false, network_id);
        let expected_result = "stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85";

        assert_eq!(base_address, expected_result);
    }

    #[pg_test]
    fn test_extract_shelley_base_address_payment_cred() {
        let base_address = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";
        let expected_result =
            hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626")
                .expect("Failed to decode hex");
        let p_cred = crate::cardano::tools_shelley_addr_extract_payment_cred(&base_address);
        assert_eq!(p_cred, expected_result);
    }

    #[pg_test]
    fn test_extract_shelley_enterprise_address_payment_cred() {
        let enterprise_address = "addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn";
        let expected_result =
            hex::decode("7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626")
                .expect("Failed to decode hex");
        let p_cred = crate::cardano::tools_shelley_addr_extract_payment_cred(&enterprise_address);
        assert_eq!(p_cred, expected_result);
    }

    #[pg_test]
    fn test_extract_base_address_stake_cred() {
        let base_address = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";
        let expected_result =
            hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef")
                .expect("Failed to decode hex");
        let s_cred = crate::cardano::tools_shelley_addr_extract_stake_cred(&base_address);
        assert_eq!(s_cred, expected_result);
    }

    #[pg_test]
    fn test_extract_reward_address_stake_cred() {
        let reward_address = "stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85";
        let expected_result =
            hex::decode("7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef")
                .expect("Failed to decode hex");
        let s_cred = crate::cardano::tools_shelley_addr_extract_stake_cred(&reward_address);
        assert_eq!(s_cred, expected_result);
    }

    #[pg_test]
    fn test_get_addr_type() {
        let reward_address = "stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85";
        let reward_addr_type = crate::cardano::tools_shelley_addr_get_type(&reward_address);
        assert_eq!(reward_addr_type, "STK_KEY");

        let base_address = "addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm";
        let base_addr_type = crate::cardano::tools_shelley_addr_get_type(&base_address);
        assert_eq!(base_addr_type, "PMT_KEY:STK_KEY");

        let enterprise_address = "addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn";
        let enterprise_addr_type = crate::cardano::tools_shelley_addr_get_type(&enterprise_address);
        assert_eq!(enterprise_addr_type, "PMT_KEY:NONE");
    }

    #[pg_test]
    fn test_tools_verify_cip88_pool_key_registration_no_hash() {
        let cbor_data = r#"\xa1190363a3000201a5018201581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb10280038102041a08d77f10075820fb01193646bb8820cc8c1fc70752d068e1b37be2f1aef88a2bc70cf598de6a630281a201a40101032720062158201ca00b7625ea6a25a6c8c128e308877a563d133ff108147fd1edc36eca3a447c02845829a201276761646472657373581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb10058203a1807ae73acd6dc91f39fa2f6d24e0996d348bb21939e1d9bc5cd75dd778a6858406b8978326e011a9531ac55040adeba410edd9ad8d28b59ad2b7b7d5923b82745ed85155c0ba367b2e54aa8e1f91eb96a58e8249f89d5d0b1f83ba4946d808607"#;

        let query = format!(
            "SELECT is_valid FROM cardano.tools_verify_cip88_pool_key_registration('{}'::bytea);",
            cbor_data
        );

        let result: Option<bool> = Spi::get_one(&query)
            .expect("Query execution failed");

        assert_eq!(result, Some(true), "Expected is_valid to be true, but got {:?}", result);
    }

    #[pg_test]
    fn test_tools_verify_cip88_pool_key_registration_hash() {
        let cbor_data = r#"\xa1190363a3000201a5018201581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb10280038102041a08d7891a075820fb01193646bb8820cc8c1fc70752d068e1b37be2f1aef88a2bc70cf598de6a630281a201a40101032720062158201ca00b7625ea6a25a6c8c128e308877a563d133ff108147fd1edc36eca3a447c02845829a201276761646472657373581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb101581c840ab20690f19a03b8bcd3c5ee40aa4829d933a2dcc25e6b82acc57e5840301ae3df60b66323059bef0f25a508eb025c881c72c04f02745f43d2679403e48d3bd1e605b5cb948935392369c7ce2d3649a3ab6335f68730ce053e411bc407"#;

        let query = format!(
            "SELECT is_valid FROM cardano.tools_verify_cip88_pool_key_registration('{}'::bytea);",
            cbor_data
        );

        let result: Option<bool> = Spi::get_one(&query)
            .expect("Query execution failed");

        assert_eq!(result, Some(true), "Expected is_valid to be true, but got {:?}", result);
    }

    #[pg_test]
    fn test_tools_verify_cip88_pool_key_registration_no_hash_fail() {
        let cbor_data = r#"\xa1190363a3000201a5018201581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb10280038102041a08d77f10075820fb01193646bb8820cc8c1fc70752d068e1b37be2f1aef88a2bc70cf598de6a630281a201a40101032720062158201ca00b7625ea6a25a6c8c128e308877a563d133ff108147fd1edc36eca3a447c02845829a201276761646472657373581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb10058203a1807ae73acd6dc91f39fa2f6d24e0996d348bb21939e1d9bc5cd75dd778a6858406b8978326e011a9531ac55040adaba410edd9ad8d28b59ad2b7b7d5923b82745ed85155c0ba367b2e54aa8e1f91eb96a58e8249f89d5d0b1f83ba4946d808607"#;

        let query = format!(
            "SELECT is_valid FROM cardano.tools_verify_cip88_pool_key_registration('{}'::bytea);",
            cbor_data
        );

        let result: Option<bool> = Spi::get_one(&query)
            .expect("Query execution failed");

        assert_eq!(result, Some(false));
    }

    #[pg_test]
    fn test_tools_verify_cip88_pool_key_registration_hash_fail() {
        let cbor_data = r#"\xa1190363a3000201a5018201581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb10280038102041a08d7891a075820fb01193646bb8820cc8c1fc70752d068e1b37be2f1aef88a2bc70cf598de6a630281a201a40101032720062158201ca00b7625ea6a25a6c8c128e308877a563d133ff108147fd1edc36eca3a447c02845829a201276761646472657373581c6648d73a09b282c120c8476789f8232b7eead94ff560917ae8fc4eb101581c840ab20690f19a03b8bcd3c5ee40aa4829d933a2dcc25e6b82acc57e5840301ae3df60b66323059befaf25a508eb025c881c72c04f02745f43d2679403e48d3bd1e605b5cb948935392369c7ce2d3649a3ab6335f68730ce053e411bc407"#;

        let query = format!(
            "SELECT is_valid FROM cardano.tools_verify_cip88_pool_key_registration('{}'::bytea);",
            cbor_data
        );

        let result: Option<bool> = Spi::get_one(&query)
            .expect("Query execution failed");

        assert_eq!(result, Some(false));
    }
}
