CREATE OR REPLACE FUNCTION cardano.tools_verify_cip88_pool_key_registration(cbor_data BYTEA)
    RETURNS TABLE (is_valid BOOLEAN) AS $$
BEGIN
RETURN QUERY
    WITH
            decoded_jsonb AS (
                SELECT "cardano"."cbor_decode_jsonb_hex2bytea"(cbor_data) AS json_data
            ),
            parsed_fields AS (
                SELECT
                    "cardano"."cbor_encode_jsonb"(json_data#>'{867, 2, 0, 2, 0}') AS protected_header,
                    "cardano"."blake2b_hash"("cardano"."cbor_encode_jsonb"(json_data#>'{867, 1}'), 32) AS payload,
                    (json_data#>>'{867, 2, 0, 2, 0, address}')::"bytea" AS address,
                    (json_data#>>'{867, 2, 0, 1, -2}')::"bytea" AS pubkey,
                    (json_data#>>'{867, 2, 0, 2, 1}')::"int2" AS need_hash,
                    (json_data#>>'{867, 2, 0, 2, 3}')::"bytea" AS signature
                FROM decoded_jsonb
            )
SELECT
    cardano.ed25519_verify_signature(
            pubkey,
            message,
            signature
    ) AND ("address" = "expected_address") AS is_valid
FROM parsed_fields, LATERAL (
                             SELECT
                                 "cardano"."cbor_encode_jsonb"(
                                         jsonb_build_array(
                                                 'Signature1',
                                                 protected_header,
                                                 ''::bytea,
                                                 CASE
                                                     WHEN need_hash = 1 THEN cardano.blake2b_hash(payload, 28)
                                                     ELSE payload
                                                     END
                                         )
                                 ) AS message,
                                 "cardano".blake2b_hash("pubkey", 28) AS expected_address
    ) subquery;
END;
$$ LANGUAGE plpgsql;

CREATE  FUNCTION cardano."cbor_decode_jsonb_hex2bytea"(
    "cbor_bytes" bytea /* &[u8] */
) RETURNS jsonb /* pgrx::datum::json::JsonB */
    STRICT
    LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'cbor_decode_jsonb_hex2bytea_wrapper';

