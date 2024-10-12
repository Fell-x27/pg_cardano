# Contents

1. [About this project](#about-this-project)
3. [Installing Pre-built Binaries](#installing-pre-built-binaries)
4. [Building from sources](#building-from-sources)
    - [0. Requirements](#0-requirements)
    - [1. Install Rust](#1-install-rust)
    - [2. Clone the Repository and install dependencies](#2-clone-the-repository-and-install-dependencies)
    - [3. Test the Extension](#3-test-the-extension-optional)
    - [4. Build and Install the Extension](#4-build-and-install-the-extension)
6. [Using the Extension](#using-the-extension)
    - [Create the Extension in PostgreSQL](#create-the-extension-in-postgresql)
    - [Examples](#examples)
      - [Base58 Encoding and Decoding](#base58-encoding-and-decoding)
      - [Bech32 Encoding and Decoding](#bech32-encoding-and-decoding)
      - [CBOR Encoding and Decoding](#cbor-encoding-and-decoding)
      - [Blake2b Hashing](#blake2b-hashing)
      - [Ed25519 Signing and Verification](#ed25519-signing-and-verification)
      - [dRep View ID Builders](#drep-view-id-builders)
      - [Shelley Address Utilities](#shelley-address-utilities)

## About this project

This extension is an attempt to create a Swiss Army knife for simplifying the work with binary data in **Cardano db-sync**, as well as automating some processes.

It is written in **Rust**, which ensures high security and excellent performance.

The extension is designed to handle unforeseen errors gracefully, without causing any disruptions in the database's operation. All errors are safely propagated as PostgreSQL-level error messages.

This extension is developed with the support of the 💜 **Medusa Development Support [MDS]** 💜 stake pool .


# Installing Pre-built Binaries

1. Download the latest version from the releases page.
2. Unpack the `.tar.gz` archive.
3. Navigate to the unpacked directory and run:
    ```bash
    ./install.sh
    ```
   That's it!
4. If you want to remove the extension, run:
    ```bash
    ./uninstall.sh
    ```
   from the same directory, of course.

Then jump to the [Using paragraph](#using-the-extension)!

# Building from sources

## 0. Requirements

To use this extension, you will need the following:

- **Operating System:** Linux (Debian-based or RHEL-based distributions recommended)
- **PostgreSQL Version:** 12 or higher
- **Dependencies:**
    - For Debian-based systems:
      ```bash
      sudo apt update && sudo apt install libclang-dev clang git curl build-essential libreadline-dev zlib1g-dev flex bison libxml2-dev libxslt-dev libssl-dev libxml2-utils xsltproc ccache pkg-config
      ```           
    - For RHEL-based systems:
      ```bash
      sudo yum makecache && sudo yum install clang clang-devel git curl bison-devel readline-devel zlib-devel openssl-devel wget ccache && sudo yum groupinstall -y 'Development Tools'
      ```

Make sure that all required dependencies are installed before proceeding with the installation of the extension.

## 1. Install Rust

Ensure that Rust is installed on your system. Use the following command to install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 2. Clone the Repository and install dependencies

```bash
git clone https://github.com/Fell-x27/pg_cardano.git
cd pg_cardano
cargo install cargo-pgrx
cargo pgrx init
```

By default, `pgrx` will build environments for PostgreSQL versions 12 through 17. During installation, your database version will be detected automatically. However, the build process can take a long time, so you may want to remove the unnecessary versions from `cargo.toml` and switch the default to the remaining one.

Or, you can just leave it as is.

## 3. Test the Extension (OPTIONAL)

Inside the project directory run tests to be sure if everything is fine:
```bash
cargo build && cargo test --package pg_cardano --lib tests
```

Optionally, you can check the extension in a sandboxed PostgreSQL instance with:
```bash
cargo pgrx run
```
remember - you still have to activate the extension manually, see ["Using the Extension"](#using-the-extension)

## 4. Build and Install the Extension

Then build the extension using the following command:
```bash
cargo pgrx package
```
If it fails, check if PostgreSQL is installed.

Then you can install it right to your database:
```bash
cargo pgrx install --no-default-features --release --sudo
```

You are awesome!

# Using the Extension
## Create the Extension in PostgreSQL

In order to use it, you need to create it in your PostgreSQL database:
```sql
CREATE EXTENSION pg_cardano;
```

If you already have it installed and want to update to a new version, you can update it with:
```sql
ALTER EXTENSION pg_cardano UPDATE;
```

You can also remove it (along with any dependent objects) with:
```sql
DROP EXTENSION pg_cardano CASCADE;
```

If you see errors during an update or reinstallation, try restarting your PostgreSQL server — it's fine :)

## Examples

After creating the extension, you can use the various cryptographic and utility functions it provides. Below are examples of how to use these functions.

### **Base58 Encoding and Decoding**

You can encode a string of bytes into Base58 or decode a Base58-encoded string back to bytes.

- **Encode to Base58:**

```sql
SELECT cardano.base58_encode('Cardano'::bytea);  
-- Returns '3Z6ioYHE3x'
```

- **Decode from Base58:**

```sql
SELECT cardano.base58_decode('3Z6ioYHE3x');  
-- Returns '\x43617264616e6f' (hex for 'Cardano')
```
---
### **Bech32 Encoding and Decoding**

You can encode data using Bech32 with a custom human-readable prefix (HRP) or decode Bech32-encoded strings.

- **Encode to Bech32:**

```sql
SELECT cardano.bech32_encode(
        'ada', --prefix
        'is amazing'::bytea --data
);  
-- Returns 'ada1d9ejqctdv9axjmn8dypl4d'
```

- **Decode Bech32 prefix:**

```sql
SELECT cardano.bech32_decode_prefix('ada1d9ejqctdv9axjmn8dypl4d');  
-- Returns 'ada'
```

- **Decode Bech32 data:**

```sql
SELECT cardano.bech32_decode_data('ada1d9ejqctdv9axjmn8dypl4d');  
-- Returns '\x697320616d617a696e67' (hex for 'is amazing')
```
---
### **CBOR Encoding and Decoding**

Encode JSONB data to CBOR format or decode CBOR back to JSONB.

- **Encode JSONB to CBOR:**

```sql
SELECT cardano.cbor_encode_jsonb('{"ada": "is amazing!", "version": 1.0}'::jsonb);  
-- Returns '\xa2636164616b697320616d617a696e67216776657273696f6ef93c00'
```

- **Decode CBOR to JSONB:**

```sql
SELECT cardano.cbor_decode_jsonb('\xa2636164616b697320616d617a696e67216776657273696f6ef93c00'::bytea);  
-- Returns '{"ada":"is amazing!","version":1.0}'
```
---
### **Blake2b Hashing**

Hash data using the Blake2b algorithm with a specified output length (between 1 and 64 bytes).

- **Hash with Blake2b:**

```sql
SELECT cardano.blake2b_hash(
        'Cardano is amazing!'::bytea, --message
        32 --length up to 64
);  
-- Returns '\x2244d5c9699fa93b0a8ed3ae952f88c9b872177e8a8ffcd8126a0d69e6806545'
```
---
### **Ed25519 Signing and Verification**

Sign a message using Ed25519 and verify a signature.

- **Sign a message:**

```sql
SELECT cardano.ed25519_sign_message(
        '\x43D68AECFA7B492F648CE90133D10A97E4300FB3C08B5D843F05BDA7EF53B3E3'::bytea, --signing key
        'Cardano is amazing!'::bytea);  --message
-- Returns '\x74265f96e48ef1751f7c9cb3c5d376130664f6e00518fefd10fb627112ef6dd29c424d335f236aeca9657b914fec5db9c0412e69858776b03a8fe476c0e7600f'
```

- **Verify a signature:**

```sql
SELECT cardano.ed25519_verify_signature(
  '\x432753BDFD91EA3E2DA1E3A0784D090D7088E2B176AE7C11DFA2D75E2A6C12FB'::bytea, --verification key
  'Cardano is amazing!'::bytea, --message
  '\x74265f96e48ef1751f7c9cb3c5d376130664f6e00518fefd10fb627112ef6dd29c424d335f236aeca9657b914fec5db9c0412e69858776b03a8fe476c0e7600f'::bytea --signature
);  
-- Returns 't' for 'true'
```
---
### **dRep View ID Builders**

You can generate dRep View IDs according to CIP-105 and CIP-129 specifications.

- **Encode dRep ID (CIP-105),  using public key:**

```sql
SELECT cardano.tools_drep_id_encode_cip105(
        '\x28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155'::bytea, --raw id
        FALSE --is it script?
);  
-- Returns 'drep19qg34ctllr7lh48nnj4akfc978qzqzuwzkgsdu6r3zc42e5y854'
```

- **Encode dRep ID (CIP-129), using script:**

```sql
SELECT cardano.tools_drep_id_encode_cip129(
        '\x28111ae17ff8fdfbd4f39cabdb2705f1c0200b8e159106f34388b155'::bytea, --raw id
        TRUE --is it script?
);  
-- Returns 'drep1yv5pzxhp0lu0m7757ww2hke8qhcuqgqt3c2ezphngwytz4gj324g7'
```
---
### **Shelley Address Utilities**

Build and extract data from Shelley addresses.

- **Build Shelley base address:**

```sql
SELECT cardano.tools_shelley_address_build(
  '\x7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626'::bytea, --payment cred
  FALSE, --is payment cred a script?
  '\x7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef'::bytea, --stake cred
  FALSE,  --is stake cred a script?
  0 -- network id
);  
-- Returns 'addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm'
```

- **Build Shelley enterprise address:**

```sql
SELECT cardano.tools_shelley_address_build(
  '\x7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626'::bytea, --payment cred
  FALSE, --is payment cred a script?
  ''::bytea, --stake cred (empty for an enterprise address)
  FALSE, --is stake cred a script? (actually, it will be ignored anyway in this case)
  0  -- network id
);  
-- Returns 'addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn'
```

- **Build Shelley reward address:**

```sql
SELECT cardano.tools_shelley_address_build(
  ''::bytea, --payment cred (empty for a stake address)
  FALSE,  --is payment cred a script? (actually, it will be ignored anyway in this case)
  '\x7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef'::bytea, --stake cred 
  FALSE, --is stake cred a script?
  0  -- network id
);  
-- Returns 'stake_test1up7r4chjzawrmzrtnk42xcjn8d7mrvcdkmet47hdw457amcl9yr85'
```

- **Extract payment credential from base address(also will work with any enterprise address):**

```sql
SELECT cardano.tools_shelley_addr_extract_payment_cred('addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm');  
-- Returns '\x7415251fc7df0983fb1809b8b27e2d4578d8b7ca336be8656627e626'
```

- **Extract stake credential from base address(also will work with any stake address):**

```sql
SELECT cardano.tools_shelley_addr_extract_stake_cred('addr_test1qp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfnu8t30y96u8kyxh8d25d39xwmakxesmdhjhtaw6atfamhsplwypm');  
-- Returns '\x7c3ae2f2175c3d886b9daaa362533b7db1b30db6f2bafaed7569eeef'
```

- **Get Shelley Address type:**

```sql
SELECT cardano.tools_shelley_addr_get_type('addr_test1vp6p2fglcl0snqlmrqym3vn794zh3k9hegekh6r9vcn7vfspyp8fn');  
-- Returns 'PMT_KEY:NONE
-- Available options:
--         "PMT_KEY:STK_KEY",
--         "PMT_SCRIPT:STK_KEY",
--         "PMT_KEY:STK_SCRIPT",
--         "PMT_SCRIPT:STK_SCRIPT",
--         "PMT_KEY:POINTER",
--         "PMT_SCRIPT:POINTER",
--         "PMT_KEY:NONE",
--         "PMT_SCRIPT:NONE"
--         "STK_KEY"
--         "STK_SCRIPT"
--         "UNKNOWN"
```
