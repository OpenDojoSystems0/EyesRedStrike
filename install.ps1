# EyesRedStrike — installateur Windows
# Usage : irm https://raw.githubusercontent.com/OpenDojoSystems0/EyesRedStrike/main/install.ps1 | iex
$ErrorActionPreference = "Stop"

$RepoUrl    = "https://github.com/OpenDojoSystems0/EyesRedStrike.git"
$InstallDir = if ($env:EYESREDSTRIKE_HOME) { $env:EYESREDSTRIKE_HOME } else { Join-Path $env:USERPROFILE ".eyesredstrike" }
$AppDir     = Join-Path $InstallDir "app"
$VenvDir    = Join-Path $InstallDir "venv"
$BinDir     = Join-Path $env:USERPROFILE ".local\bin"
$ShimPath   = Join-Path $BinDir "eyesredstrike.cmd"

function Write-Info($msg)  { Write-Host "==> $msg" -ForegroundColor DarkGray }
function Write-Ok($msg)    { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Fail($msg)  { Write-Host "ERREUR: $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  EyesRedStrike -- installation" -ForegroundColor Red
Write-Host "  by Open Dojo Systems" -ForegroundColor DarkGray
Write-Host ""

# --- Prérequis -----------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Fail "git est requis mais introuvable. Installez Git for Windows (https://git-scm.com/download/win) puis relancez ce script."
}

$PythonBin = $null
foreach ($candidate in @("python", "python3", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        try {
            $versionOutput = & $candidate -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>$null
            if ($versionOutput) {
                $parts = $versionOutput.Split(".")
                if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 9) {
                    $PythonBin = $candidate
                    break
                }
            }
        } catch {}
    }
}
if (-not $PythonBin) {
    Write-Fail "Python >= 3.9 est requis mais introuvable. Installez-le depuis python.org (cochez 'Add to PATH') puis relancez ce script."
}
Write-Ok "Python détecté : $(& $PythonBin --version)"

# --- Récupération du code -------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if (Test-Path (Join-Path $AppDir ".git")) {
    Write-Info "Installation existante détectée -- mise à jour..."
    git -C $AppDir pull --ff-only
} else {
    Write-Info "Téléchargement d'EyesRedStrike dans $AppDir..."
    git clone --depth 1 $RepoUrl $AppDir
}

# --- Environnement virtuel + dépendances ----------------------------------
Write-Info "Création de l'environnement virtuel..."
& $PythonBin -m venv $VenvDir

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
Write-Info "Installation des dépendances (yara-python, psutil, colorama, requests)..."
& $VenvPython -m pip install --quiet --upgrade pip
& $VenvPython -m pip install --quiet -e $AppDir

# --- Wrapper exécutable ----------------------------------------------------
# On délègue au script console généré par pip (venv/Scripts/eyesredstrike.exe) plutôt
# qu'à "python -m eyesredstrike" : ce dernier ajoute le répertoire courant (cwd) en
# tête de sys.path, ce qui peut faire planter l'import si le cwd contient un dossier
# nommé "eyesredstrike"/"EyesRedStrike" (collision de nom de paquet).
$VenvEntryPoint = Join-Path $VenvDir "Scripts\eyesredstrike.exe"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
@"
@echo off
"$VenvEntryPoint" %*
"@ | Set-Content -Path $ShimPath -Encoding ASCII

Write-Ok "Commande installée : $ShimPath"

# --- PATH check ------------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
    Write-Host ""
    Write-Host "⚠  $BinDir a été ajouté à votre PATH utilisateur." -ForegroundColor Yellow
    Write-Host "   Rouvrez votre terminal (PowerShell/cmd) pour que ça prenne effet." -ForegroundColor Yellow
}

Write-Host ""
Write-Ok "Installation terminée !"
Write-Host "   Lancez : eyesredstrike               (menu interactif)"
Write-Host "   Ou      : eyesredstrike scan `$env:USERPROFILE\Downloads"
Write-Host ""
