#!/bin/bash

BOLD="\e[1m"
RESET="\e[0m"
YELLOW="\e[33m"
GREEN="\e[32m"
BLUE="\e[34m"
RED="\e[31m"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v pg_config &> /dev/null; then
  echo -e "${BOLD}${RED}Error: pg_config not found.${RESET}"
  echo -e "${BOLD}${YELLOW}Please install the PostgreSQL development package for your system.${RESET}"
  exit 1
fi

get_pg_config_value() {
  local key="$1"
  pg_config | grep "$key" | cut -d '=' -f 2 | xargs
}

# Description : Exit with error message
#             : $1 = Error message we'd like to display before exiting (function will pre-fix 'ERROR: ' to the argument)
err_exit() {
  printf "${BOLD}${RED}ERROR: ${1} ${RESET}\n" >&2
  echo -e "Exiting...\n" >&2
  pushd -0 >/dev/null && dirs -c
  exit 1
}

PG_VERSION=$(get_pg_config_value "VERSION" | awk '{print $2}' | cut -d'.' -f1)
SHAREDIR=$(get_pg_config_value "SHAREDIR")
PKGLIBDIR=$(get_pg_config_value "PKGLIBDIR")

echo -e "${BOLD}${YELLOW}Detected PostgreSQL major version: $PG_VERSION${RESET}"
echo -e "${BOLD}${YELLOW}Detected SHAREDIR: $SHAREDIR${RESET}"
echo -e "${BOLD}${YELLOW}Detected PKGLIBDIR: $PKGLIBDIR${RESET}"

if [ -z "$PG_VERSION" ] || [ -z "$SHAREDIR" ] || [ -z "$PKGLIBDIR" ]; then
  echo -e "${BOLD}${RED}Error: Failed to detect PostgreSQL paths.${RESET}"
  exit 1
fi

BIN_DIR="./bin/pg$PG_VERSION"
MIGRATIONS_DIR="./migrations"

if [ ! -d "$BIN_DIR" ]; then
  BIN_DIR="$DIR/../pg_cardano/bin/pg$PG_VERSION"
  MIGRATIONS_DIR="$DIR/../pg_cardano/migrations"
fi

[ -d "$BIN_DIR" ] || err_exit "Directory with pre-built extension for PostgreSQL $PG_VERSION not found."

echo -e "${BOLD}${GREEN}Found extension directory: $BIN_DIR${RESET}"

echo -e "${BOLD}${BLUE}Now copying files to system directories, this requires sudo privileges.${RESET}"

sudo mkdir -p "$SHAREDIR"
sudo mkdir -p "$SHAREDIR/extension/"
sudo mkdir -p "$PKGLIBDIR"

sudo cp "$MIGRATIONS_DIR"/*.control "$SHAREDIR/extension/" 2>/dev/null || err_exit "Failed to copy control files to $SHAREDIR/extension."

sudo cp "$MIGRATIONS_DIR"/*.sql "$SHAREDIR/extension/" 2>/dev/null || err_exit "Failed to copy SQL files to $SHAREDIR/extension."

sudo cp "$BIN_DIR"/*.so "$PKGLIBDIR/" 2>/dev/null || err_exit "Failed to copy .so files to $PKGLIBDIR."

echo -e "${BOLD}${GREEN}========================================${RESET}"
echo -e "${BOLD}${GREEN}EXTENSION PG_CARDANO IS READY TO USE!${RESET}"
echo -e "${BOLD}${GREEN}========================================${RESET}"

echo -e "Don't forget to activate the extension in your database!"
echo -e " \n1) To create the extension, run the following command in your PostgreSQL instance:"
echo -e "   ${BOLD}CREATE EXTENSION pg_cardano;${RESET}"

echo -e "\n2) If the extension already exists, you can update it to the latest version:"
echo -e "   ${BOLD}ALTER EXTENSION pg_cardano UPDATE;${RESET}"

echo -e "\nFor more information, you can refer to the official documentation:"
echo -e "   ${BLUE}https://github.com/cardano-community/pg_cardano/blob/master/README.md${RESET}"

