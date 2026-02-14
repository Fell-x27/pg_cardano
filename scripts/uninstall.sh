#!/bin/bash
# Uninstalls pg_cardano files from PostgreSQL system directories for the detected version.
# Removes extension SQL/control files and shared library artifacts using sudo.

BOLD=$(tput bold)
RESET=$(tput sgr0)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
BLUE=$(tput setaf 4)

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

PG_VERSION=$(get_pg_config_value "VERSION" | awk '{print $2}' | cut -d'.' -f1)
SHAREDIR=$(get_pg_config_value "SHAREDIR")
PKGLIBDIR=$(get_pg_config_value "PKGLIBDIR")

echo "${BOLD}${YELLOW}Detected PostgreSQL major version: $PG_VERSION${RESET}"
echo "${BOLD}${YELLOW}Detected SHAREDIR: $SHAREDIR${RESET}"
echo "${BOLD}${YELLOW}Detected PKGLIBDIR: $PKGLIBDIR${RESET}"

if [ -z "$PG_VERSION" ] || [ -z "$SHAREDIR" ] || [ -z "$PKGLIBDIR" ]; then
  echo "${BOLD}${RED}Error: Failed to detect PostgreSQL paths.${RESET}"
  exit 1
fi

echo "${BOLD}${BLUE}Now deleting pg_cardano related files from system directories. This requires sudo privileges.${RESET}"

echo "${BOLD}${BLUE}Removing .control and .sql files from ${SHAREDIR}/extension...${RESET}"
sudo find "$SHAREDIR/extension" -name "pg_cardano.control" -exec rm -f {} \;
sudo find "$SHAREDIR/extension" -name "pg_cardano--*.sql" -exec rm -f {} \;

echo "${BOLD}${BLUE}Removing .so files from ${PKGLIBDIR}...${RESET}"
sudo find "$PKGLIBDIR" \( -name "pg_cardano.so" -o -name "pg_cardano.dylib" \) -exec rm -f {} \;

echo "${BOLD}${GREEN}All pg_cardano related files have been successfully removed!${RESET}"

echo ""
echo "${BOLD}${YELLOW}REMINDER: Don't forget to remove the extension from PostgreSQL.${RESET}"
echo "   To drop the extension, run this command in your database:"
echo "   ${BOLD}DROP EXTENSION pg_cardano;${RESET}"
