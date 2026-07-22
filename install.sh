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
# On délègue au script console généré par pip (venv/bin/eyesredstrike) plutôt qu'à
# "python -m eyesredstrike" : ce dernier ajoute le répertoire courant (cwd) en tête
# de sys.path, ce qui peut faire planter l'import si le cwd contient un dossier nommé
# "eyesredstrike"/"EyesRedStrike" (collision de nom de paquet, notamment sur les
# systèmes de fichiers insensibles à la casse comme APFS/macOS par défaut).
mkdir -p "$BIN_DIR"
cat > "$SHIM_PATH" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/eyesredstrike" "\$@"
EOF
chmod +x "$SHIM_PATH"
ok "Commande installée : $SHIM_PATH"

# --- PATH : ajout automatique aux fichiers de config du shell -------------
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
RC_UPDATED=()

add_path_to_rc() {
    local rc_file="$1"
    [ -f "$rc_file" ] || touch "$rc_file"
    if ! grep -qF "$PATH_LINE" "$rc_file" 2>/dev/null; then
        {
            echo ""
            echo "# Ajouté par l'installateur EyesRedStrike"
            echo "$PATH_LINE"
        } >> "$rc_file"
        RC_UPDATED+=("$rc_file")
    fi
}

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;  # déjà dans le PATH de cette session, rien à faire
    *)
        # On met à jour tous les fichiers de config pertinents (pas seulement celui du
        # $SHELL courant) : sur macOS, Terminal.app lance un shell de login qui ne lit
        # que .bash_profile (pas .bashrc), alors que d'autres outils s'attendent à .bashrc.
        case "$(basename "${SHELL:-}")" in
            zsh)  add_path_to_rc "$HOME/.zshrc" ;;
            bash) add_path_to_rc "$HOME/.bash_profile"; add_path_to_rc "$HOME/.bashrc" ;;
            *)    add_path_to_rc "$HOME/.profile" ;;
        esac

        # Export immédiat pour que la commande soit utilisable dès la fin de CE script
        # (ex: si l'utilisateur enchaîne avec `eyesredstrike` dans le même terminal après
        # un `source <(curl ...)`) — n'affecte pas le shell parent sinon, d'où le rappel.
        export PATH="$BIN_DIR:$PATH"

        if [ "${#RC_UPDATED[@]}" -gt 0 ]; then
            echo ""
            ok "PATH mis à jour automatiquement dans : ${RC_UPDATED[*]}"
            echo -e "   ${DIM}Ouvrez un nouveau terminal (ou lancez : source ${RC_UPDATED[0]}) pour que ça prenne effet.${RESET}"
        fi
        ;;
esac

echo ""
ok "Installation terminée !"
echo -e "   Lancez : ${BOLD}eyesredstrike${RESET}   ${DIM}(menu interactif)${RESET}"
echo -e "   Ou      : ${BOLD}eyesredstrike scan ~/Downloads${RESET}"
echo ""
