<div align="center">

```
──────────────────────────────────────────────────────────

            .--------------------------------.
            (               ●                )
            '--------------------------------'

 ███████╗██╗   ██╗███████╗███████╗██████╗ ███████╗██████╗
 ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗
 █████╗   ╚████╔╝ █████╗  ███████╗██████╔╝█████╗  ██║  ██║
 ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║██╔══██╗██╔══╝  ██║  ██║
 ███████╗   ██║   ███████╗███████║██║  ██║███████╗██████╔╝
 ╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝
      ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
      ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
      ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
      ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
      ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
      ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

     scan · analyse · extermine
     Antivirus offensif cross-platform — Windows · Linux · macOS
──────────────────────────────────────────────────────────
```

**Scanner de malwares cross-platform avec quarantaine réversible**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#installation)

*by [Open Dojo Systems](https://github.com/OpenDojoSystems0)*

</div>

---

## Sommaire

- [Ce que ça détecte](#ce-que-ça-détecte)
- [Installation rapide](#installation-rapide)
- [Utilisation](#utilisation)
- [Menu interactif](#menu-interactif)
- [Ce que cet outil est — et n'est pas](#ce-que-cet-outil-est--et-nest-pas)
- [Architecture](#architecture)
- [Limites connues](#limites-connues)
- [Contribuer](#contribuer)
- [Licence](#licence)

## Ce que ça détecte

EyesRedStrike combine **3 couches de détection** (le même modèle que les EDR/AV sérieux) :

| Couche | Rôle |
|---|---|
| **Hash IOC** | Comparaison SHA-256 contre une base d'indicateurs de compromission connus (synchronisable depuis [MalwareBazaar](https://bazaar.abuse.ch/)) |
| **Règles YARA** | Détection de patterns/techniques dans le contenu des fichiers |
| **Heuristiques** | Entropie, packers, obfuscation de scripts |

Familles couvertes par les règles fournies :

- 🎯 `Trojan:Win32/Wacatac.B!ml` et `Trojan:Script/Wacatac.B!ml`
- 🚪 Backdoors — reverse shells, webshells, backdoor SSH (`authorized_keys`), rootkits `LD_PRELOAD`
- 🔒 Ransomware — suppression de shadow copies/backups, notes de rançon
- ⛏️ Cryptomineurs — XMRig et dérivés, pools de minage cachés
- 🔑 Vol d'identifiants — dump LSASS/Mimikatz, bypass AMSI/Defender, ciblage de wallets crypto
- 🎣 Infostealers, keyloggers, RATs commerciaux courants

## Installation rapide

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/OpenDojoSystems0/EyesRedStrike/main/install.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/OpenDojoSystems0/EyesRedStrike/main/install.ps1 | iex
```

L'installateur détecte Python, crée un environnement virtuel isolé, installe les dépendances et rend la commande `eyesredstrike` disponible globalement. Aucune installation système, aucun conflit avec votre Python existant.

### Depuis les sources

```bash
git clone https://github.com/OpenDojoSystems0/EyesRedStrike.git
cd EyesRedStrike
python3 -m venv venv && source venv/bin/activate   # Windows : venv\Scripts\activate
pip install -e .
```

## Utilisation

```bash
# Menu interactif (le plus simple pour débuter)
eyesredstrike

# Scanner un dossier (rapport seul, rien n'est modifié)
eyesredstrike scan ~/Downloads

# Scanner + mettre en quarantaine automatiquement en une commande
eyesredstrike clean ~/Downloads

# Vérifier les points de démarrage (registry/cron/systemd/launchd)
eyesredstrike persistence

# Vérifier les processus et connexions réseau suspects
eyesredstrike processes

# Gérer la quarantaine
eyesredstrike quarantine list
eyesredstrike quarantine restore <id>     # faux positif -> restaurer
eyesredstrike quarantine purge <id>       # confirmé malveillant -> suppression définitive

# Mettre à jour la base d'IOCs depuis MalwareBazaar (abuse.ch)
eyesredstrike update-iocs
```

Aide détaillée avec exemples pour chaque commande : `eyesredstrike <commande> --help`

## Menu interactif

Lancer `eyesredstrike` sans argument ouvre un menu numéroté qui boucle après chaque action — pas besoin de retaper la commande à chaque fois :

```
MENU PRINCIPAL
──────────────
  1  Scanner un dossier/fichier (rapport seul)
  2  Nettoyer (scan + quarantaine automatique)
  3  Vérifier les points de persistance (registry/cron/launchd)
  4  Vérifier les processus/connexions suspects
  5  Quarantaine : lister
  6  Quarantaine : restaurer un fichier
  7  Quarantaine : supprimer définitivement (purge)
  8  Mettre à jour la base d'IOCs (MalwareBazaar)
  0  Quitter
```

## Ce que cet outil est — et n'est pas

**Est** : un scanner à la demande basé sur trois couches de détection avec mise en quarantaine réversible, conçu pour l'analyse et la réponse à incident.

**N'est pas** : un outil infaillible. Aucun scanner ne l'est — ni Defender, ni Kaspersky, ni personne. `Wacatac.B!ml` en particulier est une détection **heuristique/ML** de Microsoft Defender, pas une signature fixe : elle produit régulièrement des faux positifs sur des exécutables packés ou obfusqués mais légitimes (PyInstaller, Electron non signés, etc.). C'est pourquoi **la quarantaine est réversible par défaut** — rien n'est supprimé définitivement sans confirmation explicite (`quarantine purge`).

Ce n'est pas non plus un remplacement d'un antivirus temps réel : pas de driver kernel, pas de protection au démarrage. C'est un outil de scan à la demande.

## Architecture

```
eyesredstrike/
├── core/
│   ├── hashdb.py          # Base d'IOCs (SHA-256) + lookup
│   ├── yara_engine.py     # Moteur de règles YARA
│   ├── heuristics.py      # Entropie, packers, patterns d'obfuscation
│   ├── quarantine.py      # Mise en quarantaine réversible + restauration
│   ├── scanner.py         # Orchestrateur (walk FS, agrège les 3 couches)
│   └── ioc_update.py      # Synchronisation avec MalwareBazaar
├── platform/
│   ├── persistence.py     # Points de persistance (registry/cron/systemd/launchd)
│   └── processes.py       # Processus + connexions réseau suspectes
├── data/
│   └── iocs.json          # Base de hashs connus (enrichie via `update-iocs`)
├── rules/
│   ├── wacatac.yar           # Heuristiques droppers/scripts obfusqués type Wacatac
│   ├── generic_trojans.yar   # Keyloggers, infostealers navigateur, RATs commerciaux
│   ├── backdoors.yar         # Reverse shells, webshells, SSH backdoor, rootkit LD_PRELOAD
│   ├── ransomware.yar        # Shadow copies, notes de rançon, chiffrement de masse
│   ├── cryptominers.yar      # XMRig et dérivés
│   └── credential_theft.yar  # Dump LSASS/Mimikatz, bypass AMSI/Defender, wallets
└── cli.py                 # Interface en ligne de commande + menu interactif
```

## Limites connues

- La détection heuristique génère des faux positifs sur du code packé/obfusqué légitime — vérifiez toujours avant `purge`.
- La base `data/iocs.json` est vide au premier lancement ; elle se peuple via `update-iocs` (nécessite une [clé API gratuite MalwareBazaar](https://bazaar.abuse.ch/api/#get_apikey)) ou en l'alimentant manuellement.
- Les commandes `persistence`/`processes` peuvent nécessiter des privilèges administrateur/root pour une visibilité complète.

## Contribuer

Les contributions sont bienvenues — nouvelles règles YARA, nouveaux IOCs, corrections de faux positifs, support de plateformes additionnelles. Ouvrez une [issue](https://github.com/OpenDojoSystems0/EyesRedStrike/issues) ou une pull request.

## Licence

Distribué sous licence [Apache 2.0](LICENSE) — utilisation libre, y compris commerciale, avec attribution.

---

<div align="center">

**[Open Dojo Systems](https://github.com/OpenDojoSystems0)**

</div>
