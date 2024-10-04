#!/bin/bash

BOLD="\e[1m"
RESET="\e[0m"
YELLOW="\e[33m"
GREEN="\e[32m"
BLUE="\e[34m"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

get_pg_config_value() {
  local key="$1"
  pg_config | grep "$key" | cut -d '=' -f 2 | xargs
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

TARGET_DIR="./pg$PG_VERSION"

if [ ! -d "$TARGET_DIR" ]; then
  TARGET_DIR="$DIR/../binaries/pg$PG_VERSION"
fi

if [ ! -d "$TARGET_DIR" ]; then
  echo -e "${BOLD}${RED}Error: Directory with binaries for PostgreSQL $PG_VERSION not found.${RESET}"
  exit 1
fi

echo -e "${BOLD}${GREEN}Found extension directory: $TARGET_DIR${RESET}"

echo -e "${BOLD}${BLUE}Now copying files to system directories, this requires sudo privileges.${RESET}"

sudo cp "$TARGET_DIR"/*.control "$SHAREDIR/extension/" 2>/dev/null
if [ $? -ne 0 ]; then
  echo -e "${BOLD}${RED}Error: Failed to copy control files to $SHAREDIR/extension.${RESET}"
  exit 1
fi

sudo cp "$TARGET_DIR"/*.sql "$SHAREDIR/extension/" 2>/dev/null
if [ $? -ne 0 ]; then
  echo -e "${BOLD}${RED}Error: Failed to copy SQL files to $SHAREDIR/extension.${RESET}"
  exit 1
fi

sudo cp "$TARGET_DIR"/*.so "$PKGLIBDIR/" 2>/dev/null
if [ $? -ne 0 ]; then
  echo -e "${BOLD}${RED}Error: Failed to copy .so files to $PKGLIBDIR.${RESET}"
  exit 1
fi

echo -e "${BOLD}${GREEN}========================================${RESET}"
echo -e "${BOLD}${GREEN}EXTENSION PG_CARDANO IS READY TO USE!${RESET}"
echo -e "${BOLD}${GREEN}========================================${RESET}"

echo -e "\n1) Don't forget to activate the extension in your database:"
echo "   To create the extension, run the following command in your PostgreSQL instance:"
echo -e "   ${BOLD}CREATE EXTENSION pg_cardano;${RESET}"

echo -e "\n2) If the extension already exists, it's better to drop it before re-creating:"
echo "   To drop the extension, run:"
echo -e "   ${BOLD}DROP EXTENSION pg_cardano;${RESET}"

echo -e "\nFor more information, you can refer to the official documentation:"
echo -e "   ${BLUE}https://github.com/Fell-x27/pg_cardano/blob/master/README.md${RESET}"

