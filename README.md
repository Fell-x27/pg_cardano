## Installation and Usage

### 1. Install Rust

As first, you will need to install some dependencies:
#### For Debian-based systems:

```bash
sudo apt update && sudo apt install libclang-dev clang git curl
```

#### For RHEL-based systems:

```bash
sudo yum makecache && sudo yum install clang clang-devel git curl
```

Then, ensure that Rust is installed on your system. Use the following command to install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Install PostgreSQL Dependencies

You will need certain packages to build PostgreSQL and its extensions:

#### For Debian-based systems:

```bash
sudo apt-get install build-essential libreadline-dev zlib1g-dev flex bison libxml2-dev libxslt-dev libssl-dev libxml2-utils xsltproc ccache pkg-config
```

#### For RHEL-based systems:

```bash
sudo yum install -y bison-devel readline-devel zlib-devel openssl-devel wget ccache && sudo yum groupinstall -y 'Development Tools'
```

### 3. Clone the Repository and install dependencies

```bash
git clone https://github.com/Fell-x27/pg_cardano.git
cd pg_cardano
cargo install cargo-pgrx
cargo pgrx init
```

### 4. Build the Extension

Inside the project directory run tests to be sure if everything is fine:
```bash
cargo build && cargo test --package pg_cardano --lib tests
```


Then build the extension using the following command:
```bash
cargo pgrx package
```


### 5. Check and Install the Extension

You can check the extension in a sandboxed PostgreSQL instance with: 
```bash
cargo pgrx run
#remember - you still have to activate the extension manually, see step #6
```

Or you can install it right to your database:
```bash
cargo pgrx install --no-default-features --release --sudo
```

### 6. Create the Extension in PostgreSQL

In order to use, you need to create it in your PostgreSQL database.

If you already have it and want to update, drop it before:
```sql
DROP EXTENSION IF EXISTS pg_cardano CASCADE;
```

Then create it:
```sql
CREATE EXTENSION IF NOT EXISTS pg_cardano;
```

You are awesome!

### 7. Using the Extension

After the extension is successfully created, you can start using the `base58_encode` and `base58_decode` functions.

**Encode a string to Base58:**

```sql
SELECT base58_encode('hello'::bytea);
```

**Decode a Base58 string back to its original form:**

```sql
SELECT base58_decode('Cn8eVZg');
```
