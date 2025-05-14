DROP FUNCTION IF EXISTS cardano.tools_verify_cip88_pool_key_registration(BYTEA);
CREATE FUNCTION cardano."tools_verify_cip88_pool_key_registration"(
    "cbor_data" bytea /* &[u8] */
) RETURNS bool /* bool */
    STRICT
    LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'tools_verify_cip88_pool_key_registration_wrapper';