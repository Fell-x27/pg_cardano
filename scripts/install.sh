#!/bin/bash


BOLD=$(tput bold)
RESET=$(tput sgr0)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RED=$(tput setaf 1)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


if [[ "$OSTYPE" == "darwin"* ]]; then
  if ! command -v pg_config &> /dev/null; then
    BREW_PREFIX=$(brew --prefix postgresql 2>/dev/null || true)
    if [[ -n "$BREW_PREFIX" && -x "$BREW_PREFIX/bin/pg_config" ]]; then
      export PATH="$BREW_PREFIX/bin:$PATH"
      echo "${BOLD}${BLUE}Using pg_config from: $BREW_PREFIX/bin/pg_config${RESET}"
    fi
  fi
fi


if ! command -v pg_config &> /dev/null; then
  echo "${BOLD}${RED}Error: pg_config not found.${RESET}"
  echo "${BOLD}${YELLOW}Please ensure PostgreSQL is installed.${RESET}"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo ""
    echo "To install it on macOS, run:"
    echo "  ${BOLD}brew install postgresql${RESET}"
  fi
  exit 1
fi


get_pg_config_value() {
  local key="$1"
  pg_config | grep "$key" | cut -d '=' -f 2 | xargs
}

# Description : Exit with error message
#             : $1 = Error message we'd like to display before exiting (function will pre-fix 'ERROR: ' to the argument)
err_exit() {
  printf "${BOLD}${RED}ERROR: %s${RESET}\n" "$1" >&2
  echo "Exiting..." >&2
  exit 1
}

PG_VERSION=$(get_pg_config_value "VERSION" | awk '{print $2}' | cut -d'.' -f1)
SHAREDIR=$(get_pg_config_value "SHAREDIR")
PKGLIBDIR=$(get_pg_config_value "PKGLIBDIR")

echo "${BOLD}${YELLOW}Detected PostgreSQL major version: $PG_VERSION${RESET}"
echo "${BOLD}${YELLOW}Detected SHAREDIR: $SHAREDIR${RESET}"
echo "${BOLD}${YELLOW}Detected PKGLIBDIR: $PKGLIBDIR${RESET}"

if [ -z "$PG_VERSION" ] || [ -z "$SHAREDIR" ] || [ -z "$PKGLIBDIR" ]; then
  err_exit "Failed to detect PostgreSQL paths via pg_config"
fi

BIN_DIR="./bin/pg$PG_VERSION"
MIGRATIONS_DIR="./migrations"

if [ ! -d "$BIN_DIR" ]; then
  BIN_DIR="$DIR/../pg_cardano/bin/pg$PG_VERSION"
  MIGRATIONS_DIR="$DIR/../pg_cardano/migrations"
fi

[ -d "$BIN_DIR" ] || err_exit "Directory with pre-built extension for PostgreSQL $PG_VERSION not found."

echo "${BOLD}${GREEN}Found extension directory: $BIN_DIR${RESET}"
echo "${BOLD}${BLUE}Now copying files to system directories. You may be prompted for your password.${RESET}"

sudo mkdir -p "$SHAREDIR/extension" "$PKGLIBDIR" || err_exit "Failed to create target directories"

sudo cp "$MIGRATIONS_DIR"/*.control "$SHAREDIR/extension/" 2>/dev/null || err_exit "Failed to copy control files"
sudo cp "$MIGRATIONS_DIR"/*.sql "$SHAREDIR/extension/" 2>/dev/null || err_exit "Failed to copy SQL files"
sudo cp "$BIN_DIR"/* "$PKGLIBDIR/" 2>/dev/null || err_exit "Failed to copy files"

echo "${BOLD}${GREEN}========================================${RESET}"
echo "${BOLD}${GREEN}EXTENSION PG_CARDANO IS READY TO USE!${RESET}"
echo "${BOLD}${GREEN}========================================${RESET}"

echo ""
echo "1) To create the extension, run in psql:"
echo "   ${BOLD}CREATE EXTENSION pg_cardano;${RESET}"

echo ""
echo "2) To update existing extension:"
echo "   ${BOLD}ALTER EXTENSION pg_cardano UPDATE;${RESET}"

echo ""
echo "For more info:"
echo "   ${BLUE}https://github.com/cardano-community/pg_cardano/blob/master/README.md${RESET}"
