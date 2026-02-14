#!/bin/bash
# Builds distribution artifacts only for PostgreSQL versions present in both:
# ~/.pgrx/config.toml and the crate's pgXX features in Cargo.toml.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$HOME/.pgrx/config.toml"
CARGO_TOML="$DIR/../Cargo.toml"

if [ ! -f "$CARGO_TOML" ]; then
  echo "Error: Cargo.toml not found at $CARGO_TOML"
  exit 1
fi

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
      "name") PACKAGE_NAME=$(echo "$value" | tr -d '"') ;;
      "version") PACKAGE_VERSION=$(echo "$value" | tr -d '"') ;;
    esac
  fi
done < "$CARGO_TOML"

SUPPORTED_PG_FEATURES=()
in_features=false

while IFS='=' read -r key _; do
  key=$(echo "$key" | xargs)
  if [[ "$key" == "[features]" ]]; then
    in_features=true
    continue
  fi
  if $in_features && [[ "$key" == "["* ]] && [[ "$key" != "[features]" ]]; then
    in_features=false
  fi
  if $in_features && [[ "$key" =~ ^pg[0-9]+$ ]]; then
    SUPPORTED_PG_FEATURES+=("$key")
  fi
done < "$CARGO_TOML"

if [ ${#SUPPORTED_PG_FEATURES[@]} -eq 0 ]; then
  echo "No pgXX features found in [features] section of $CARGO_TOML"
  exit 1
fi

is_supported_pg_feature() {
  local feature="$1"
  for supported in "${SUPPORTED_PG_FEATURES[@]}"; do
    if [[ "$supported" == "$feature" ]]; then
      return 0
    fi
  done
  return 1
}

PG_CONFIG_KEYS=()
PG_CONFIG_PATHS=()
in_configs=false

while IFS='=' read -r key value; do
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs | tr -d '"')
  if [[ "$key" == "[configs]" ]]; then
    in_configs=true
    continue
  fi
  if $in_configs && [[ "$key" == pg* ]]; then
    PG_CONFIG_KEYS+=("$key")
    PG_CONFIG_PATHS+=("$value")
  fi
done < "$CONFIG_FILE"

if [ ${#PG_CONFIG_KEYS[@]} -eq 0 ]; then
  echo "No PostgreSQL versions found in $CONFIG_FILE"
  exit 1
fi

echo "Supported PostgreSQL features in Cargo.toml: ${SUPPORTED_PG_FEATURES[*]}"

DISTR_DIR="$DIR/../pg_cardano"
BIN_DIR="$DISTR_DIR/bin"
MIGRATIONS_DIR="$DISTR_DIR/migrations"
OUTER_SQL_DIR="$DIR/../sql"

cargo clean
rm -rf "$DISTR_DIR"
mkdir -p "$BIN_DIR" "$MIGRATIONS_DIR"

latest_suffix=""
for file in "$OUTER_SQL_DIR"/${PACKAGE_NAME}-*.sql; do
  [[ -f "$file" ]] || continue
  suffix=$(basename "$file" | sed -n "s/^${PACKAGE_NAME}--.*--\\(.*\\)\\.sql$/\\1/p")
  if [[ -z "$latest_suffix" || "$suffix" > "$latest_suffix" ]]; then
    latest_suffix="$suffix"
  fi
done

expected_file="$OUTER_SQL_DIR/${PACKAGE_NAME}--${latest_suffix}--${PACKAGE_VERSION}.sql"
if [[ "$latest_suffix" != "$PACKAGE_VERSION" && ! -f "$expected_file" ]]; then
  echo "Creating missing migration file: $expected_file"
  touch "$expected_file"
fi

matched_pg_features=0
for i in "${!PG_CONFIG_KEYS[@]}"; do
  PG_KEY="${PG_CONFIG_KEYS[$i]}"
  PG_CONFIG="${PG_CONFIG_PATHS[$i]}"

  if ! is_supported_pg_feature "$PG_KEY"; then
    echo "Skipping $PG_KEY from $CONFIG_FILE: feature not declared in Cargo.toml"
    continue
  fi
  matched_pg_features=$((matched_pg_features + 1))

  if [ -f "$PG_CONFIG" ]; then
    PG_VER_NUM=$("$PG_CONFIG" --version | awk '{print $2}' | cut -d. -f1)
    PG_VERSION="pg${PG_VER_NUM}"

    echo "Packaging for $PG_VERSION using $PG_CONFIG..."

    OUTPUT_DIR="$DIR/../target/release/pg_cardano-${PG_VERSION}"
    TARGET_DIR="$BIN_DIR/${PG_VERSION}"
    mkdir -p "$TARGET_DIR"

    cargo pgrx package --pg-config "$PG_CONFIG" --out-dir "$OUTPUT_DIR" --no-default-features

    INSTALL_DIR=$(find "$OUTPUT_DIR" -type d -name "pgrx-install")

    if [ -d "$INSTALL_DIR" ]; then
      cp "$INSTALL_DIR/lib/postgresql/"* "$TARGET_DIR/" || true
      cp "$INSTALL_DIR/share/postgresql/extension/"* "$MIGRATIONS_DIR/" || true
      echo "Files successfully extracted for $PG_VERSION"
    else
      echo "pgrx-install directory not found in $OUTPUT_DIR for $PG_VERSION"
    fi
  else
    echo "pg_config for $PG_KEY not found!"
  fi
done

if [ "$matched_pg_features" -eq 0 ]; then
  echo "No matching pgXX versions between Cargo.toml [features] and $CONFIG_FILE"
  exit 1
fi

cp "$DIR/install.sh" "$DISTR_DIR/" 2>/dev/null || true
cp "$DIR/uninstall.sh" "$DISTR_DIR/" 2>/dev/null || true
cp "$OUTER_SQL_DIR"/*.sql "$MIGRATIONS_DIR/" 2>/dev/null || true

echo "Packaging completed."
