#!/usr/bin/env bash
# EyesRedStrike — installateur macOS / Linux
# Usage : curl -fsSL https://raw.githubusercontent.com/OpenDojoSystems0/EyesRedStrike/main/install.sh | bash
set -euo pipefail

REPO_URL="https://github.com/OpenDojoSystems0/EyesRedStrike.git"
INSTALL_DIR="${EYESREDSTRIKE_HOME:-$HOME/.eyesredstrike}"
APP_DIR="$INSTALL_DIR/app"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="$HOME/.local/bin"
SHIM_PATH="$BIN_DIR/eyesredstrike"

RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
RESET='\033[0m'

info()  { echo -e "${DIM}==>${RESET} $1"; }
ok()    { echo -e "${GREEN}✓${RESET} $1"; }
fail()  { echo -e "${RED}✗ $1${RESET}" >&2; exit 1; }

echo -e "${BOLD}${RED}"
echo "  EyesRedStrike — installation"
echo -e "${RESET}${DIM}  by Open Dojo Systems${RESET}"
echo ""

# --- Prérequis ---------------------------------------------------------
command -v git >/dev/null 2>&1 || fail "git est requis mais introuvable. Installez-le puis relancez ce script."

PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version="$("$candidate" -c 'import sys; print(sys.version_info[0], sys.version_info[1])' 2>/dev/null || echo "0 0")"
        major="${version%% *}"
        minor="${version##* }"
        if [ "$major" = "3" ] && [ "$minor" -ge 9 ]; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done
[ -n "$PYTHON_BIN" ] || fail "Python >= 3.9 est requis mais introuvable. Installez-le (python.org ou votre gestionnaire de paquets) puis relancez ce script."
ok "Python détecté : $($PYTHON_BIN --version)"

# --- Récupération du code ------------------------------------------------
mkdir -p "$INSTALL_DIR"
if [ -d "$APP_DIR/.git" ]; then
    info "Installation existante détectée — mise à jour..."
    git -C "$APP_DIR" pull --ff-only
else
    info "Téléchargement d'EyesRedStrike dans $APP_DIR..."
    git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi

# --- Environnement virtuel + dépendances --------------------------------
info "Création de l'environnement virtuel..."
"$PYTHON_BIN" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

info "Installation des dépendances (yara-python, psutil, colorama, requests)..."
pip install --quiet --upgrade pip
pip install --quiet -e "$APP_DIR"
deactivate

# --- Wrapper exécutable --------------------------------------------------
mkdir -p "$BIN_DIR"
cat > "$SHIM_PATH" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" -m eyesredstrike "\$@"
EOF
chmod +x "$SHIM_PATH"
ok "Commande installée : $SHIM_PATH"

# --- PATH check -----------------------------------------------------------
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo ""
        echo -e "${RED}⚠  $BIN_DIR n'est pas dans votre PATH.${RESET}"
        echo "   Ajoutez cette ligne à votre ~/.zshrc ou ~/.bashrc puis rouvrez votre terminal :"
        echo ""
        echo -e "   ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
        echo ""
        ;;
esac

echo ""
ok "Installation terminée !"
echo -e "   Lancez : ${BOLD}eyesredstrike${RESET}   ${DIM}(menu interactif)${RESET}"
echo -e "   Ou      : ${BOLD}eyesredstrike scan ~/Downloads${RESET}"
echo ""
