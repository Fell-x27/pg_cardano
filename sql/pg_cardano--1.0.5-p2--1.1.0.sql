CREATE  FUNCTION cardano."cbor_decode_jsonb_ext"(
    "cbor_bytes" bytea /* &[u8] */
) RETURNS jsonb /* pgrx::datum::json::JsonB */
    STRICT
    LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'cbor_decode_jsonb_ext_wrapper';

CREATE  FUNCTION cardano."cbor_encode_jsonb_ext"(
    "input" jsonb /* pgrx::datum::json::JsonB */
) RETURNS bytea /* alloc::vec::Vec<u8> */
    STRICT
    LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'cbor_encode_jsonb_ext_wrapper';
