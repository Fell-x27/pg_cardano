#!/bin/bash

BOLD="\e[1m"
RESET="\e[0m"
YELLOW="\e[33m"
GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"

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

echo -e "${BOLD}${BLUE}Now deleting pg_cardano related files from system directories. This requires sudo privileges.${RESET}"

echo -e "${BOLD}${BLUE}Checking and deleting pg_cardano .control and .sql files from ${SHAREDIR}/extension...${RESET}"

sudo find "$SHAREDIR/extension" -name "pg_cardano.control" -exec rm {} \;
sudo find "$SHAREDIR/extension" -name "pg_cardano--*.sql" -exec rm {} \;

if [ $? -ne 0 ]; then
  echo -e "${BOLD}${RED}Error: Failed to remove pg_cardano control or SQL files.${RESET}"
  exit 1
fi

echo -e "${BOLD}${BLUE}Checking and deleting pg_cardano .so files from ${PKGLIBDIR}...${RESET}"

sudo find "$PKGLIBDIR" -name "pg_cardano.so" -exec rm {} \;

if [ $? -ne 0 ]; then
  echo -e "${BOLD}${RED}Error: Failed to remove pg_cardano .so files.${RESET}"
  exit 1
fi

echo -e "${BOLD}${GREEN}All pg_cardano related files have been successfully removed!${RESET}"

echo -e "\n${BOLD}${YELLOW}REMINDER: Don't forget to remove the extension from PostgreSQL.${RESET}"
echo "   To drop the extension, run the following command in your PostgreSQL instance:"
echo -e "   ${BOLD}DROP EXTENSION pg_cardano;${RESET}"
