CREATE FUNCTION cardano."tools_read_asset_name"(
    "name" bytea /* &[u8] */
) RETURNS TEXT /* alloc::string::String */
    STRICT
LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'tools_read_asset_name_wrapper';