/* <begin connected objects> */
-- src/lib.rs:83
-- pg_cardano::cardano::cbor_decode_json_mark_hex
CREATE OR REPLACE FUNCTION cardano."cbor_decode_json_mark_hex"(
    "cbor_bytes" bytea /* &[u8] */
) RETURNS TEXT /* alloc::string::String */
    STRICT
LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'cbor_decode_json_mark_hex_wrapper';
/* </end connected objects> */

/* <begin connected objects> */
-- src/lib.rs:92
-- pg_cardano::cardano::cbor_decode_jsonb_mark_hex
CREATE OR REPLACE FUNCTION cardano."cbor_decode_jsonb_mark_hex"(
    "cbor_bytes" bytea /* &[u8] */
) RETURNS jsonb /* pgrx::datum::json::JsonB */
    STRICT
LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'cbor_decode_jsonb_mark_hex_wrapper';
/* </end connected objects> */

/* <begin connected objects> */
-- src/lib.rs:64
-- pg_cardano::cardano::cbor_decode_json
CREATE OR REPLACE FUNCTION cardano."cbor_decode_json"(
    "cbor_bytes" bytea /* &[u8] */
) RETURNS TEXT /* alloc::string::String */
    STRICT
LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'cbor_decode_json_wrapper';
/* </end connected objects> */

