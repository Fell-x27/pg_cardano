#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CARGO_TOML="$DIR/../Cargo.toml"
if [ ! -f "$CARGO_TOML" ]; then
  echo "Error: Cargo.toml not found at $DIR/../"
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

if [ -z "$PACKAGE_NAME" ] || [ -z "$PACKAGE_VERSION" ]; then
  echo "Error: Could not find name or version in the [package] section of Cargo.toml."
  exit 1
fi

echo "Package name: $PACKAGE_NAME"
echo "Package version: $PACKAGE_VERSION"

DISTRO_DIR="$DIR/../pg_cardano"
if [ ! -d "$DISTRO_DIR" ]; then
  echo "Directory pg_cardano not found. Running build.sh..."
  "$DIR/build.sh"
fi

if [ ! -d "$DISTRO_DIR" ]; then
  echo "Error: Directory pg_cardano not found after build.sh."
  exit 1
fi

# Determine archive name: use first argument if provided, otherwise default
if [ $# -ge 1 ]; then
  ARCHIVE_NAME="$1"
else
  ARCHIVE_NAME="${PACKAGE_NAME}_linux_x64_v${PACKAGE_VERSION}.tar.gz"
fi

tar -czf "$DIR/$ARCHIVE_NAME" -C "$DIR/.." "$(basename "$DISTRO_DIR")"

RELEASES_DIR="$DIR/../releases"
mkdir -p "$RELEASES_DIR"

mv "$DIR/$ARCHIVE_NAME" "$RELEASES_DIR/"

echo "Archive created and moved to $RELEASES_DIR/${ARCHIVE_NAME}"