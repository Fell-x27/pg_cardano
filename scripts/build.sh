#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$HOME/.pgrx/config.toml"
CARGO_TOML="$DIR/../Cargo.toml"
if [ ! -f "$CARGO_TOML" ]; then
  echo "Error: Cargo.toml not found at $DIR/../"
  exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Configuration file not found at $CONFIG_FILE"
  exit 1
fi

in_package=false
PACKAGE_NAME=""
PACKAGE_VERSION=""

while IFS='=' read -r key value; do
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)

  if [[ "$key" == "[package]" ]]; then
    in_package=true
    continue
  fi

  if [[ "$key" == "["* ]] && [[ "$key" != "[package]" ]]; then
    in_package=false
  fi

  if $in_package; then
    case "$key" in
      "name")
        PACKAGE_NAME=$(echo "$value" | tr -d '"')
        ;;
      "version")
        PACKAGE_VERSION=$(echo "$value" | tr -d '"')
        ;;
    esac
  fi

done < "$CARGO_TOML"

in_configs=false

declare -A PG_CONFIGS

while IFS='=' read -r key value; do
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)

  if [[ "$key" == "[configs]" ]]; then
    in_configs=true
    continue
  fi

  if $in_configs && [[ "$key" == pg* ]]; then
    value=$(echo "$value" | tr -d '"')

    PG_CONFIGS["$key"]=$value
  fi

done < "$CONFIG_FILE"

if [ ${#PG_CONFIGS[@]} -eq 0 ]; then
  echo "No PostgreSQL versions found in $CONFIG_FILE"
  exit 1
fi

DISTR_DIR="$DIR/../pg_cardano"
BIN_DIR="$DISTR_DIR/bin"
MIGRATIONS_DIR="$DISTR_DIR/migrations"
OUTER_SQL_DIR="$DIR/../sql"

cargo clean
rm -rf "$DISTR_DIR"
mkdir -p "$DISTR_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$MIGRATIONS_DIR"

# Scan OUTER_SQL_DIR for migration files
latest_version=""
latest_suffix=""

for file in "$OUTER_SQL_DIR"/${PACKAGE_NAME}-*.sql; do
  if [[ -f "$file" ]]; then
    filename=$(basename "$file")
    suffix=$(echo "$filename" | sed -n "s/^${PACKAGE_NAME}--.*--\(.*\)\.sql$/\1/p")
    if [[ -z "$latest_suffix" || "$suffix" > "$latest_suffix" ]]; then
      latest_suffix="$suffix"
    fi
  fi
done

# Check if the expected migration file exists
expected_file="$OUTER_SQL_DIR/${PACKAGE_NAME}--${latest_suffix}--${PACKAGE_VERSION}.sql"
if [[ "$latest_suffix" != "$PACKAGE_VERSION" && ! -f "$expected_file" ]]; then
  echo "Creating missing migration file: $expected_file"
  touch "$expected_file"
fi

for PG_VERSION in "${!PG_CONFIGS[@]}"; do
  PG_CONFIG="${PG_CONFIGS[$PG_VERSION]}"

  if [ -f "$PG_CONFIG" ]; then
    echo "Packaging for $PG_VERSION using $PG_CONFIG..."

    OUTPUT_DIR="$DIR/../target/release/pg_cardano-${PG_VERSION}"
    TARGET_DIR="$BIN_DIR/${PG_VERSION}"
    mkdir -p "$TARGET_DIR"
    cargo pgrx package --pg-config "$PG_CONFIG" --out-dir "$OUTPUT_DIR" --no-default-features

    INSTALL_DIR=$(find "$OUTPUT_DIR" -type d -name "pgrx-install")

    if [ -d "$INSTALL_DIR" ]; then
      cp "$INSTALL_DIR/lib/postgresql/"* "$TARGET_DIR/"
      cp "$INSTALL_DIR/share/postgresql/extension/"* "$MIGRATIONS_DIR/"
      echo "Files successfully extracted;"
    else
      echo "pgrx-install directory not found in $OUTPUT_DIR for $PG_VERSION"
    fi
  else
    echo "pg_config for $PG_VERSION not found!"
  fi
done

cp "$DIR/install.sh" "$DISTR_DIR/"
cp "$DIR/uninstall.sh" "$DISTR_DIR/"
cp "$OUTER_SQL_DIR"/*.sql "$MIGRATIONS_DIR/"
echo "Packaging completed."