#!/bin/bash

CONFIG_FILE="$HOME/.pgrx/config.toml"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Configuration file not found at $CONFIG_FILE"
  exit 1
fi

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

mkdir -p "$DISTR_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$MIGRATIONS_DIR"

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