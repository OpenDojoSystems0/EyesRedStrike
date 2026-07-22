"""Interface en ligne de commande d'EyesRedStrike."""
from __future__ import annotations

import argparse
import sys
from argparse import Namespace
from pathlib import Path

from colorama import Fore, Back, Style, init as colorama_init

from . import __version__
from .core.scanner import Scanner, FileFinding
from .core.quarantine import Quarantine
from .core.hashdb import HashDB
from .platform.persistence import check_persistence
from .platform.processes import list_suspicious_processes

SEVERITY_COLOR = {
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE,
}

_R = Style.BRIGHT + Fore.RED
_DR = Fore.RED
_W = Style.BRIGHT + Fore.WHITE
_D = Style.DIM + Fore.WHITE
_RESET = Style.RESET_ALL

def _build_eye_art(width: int = 34) -> list[str]:
    """Construit un œil ASCII (paupières + pupille) avec une largeur fixe, calculée
    programmatiquement pour rester parfaitement aligné quelle que soit la police."""
    inner = width - 2
    left_pad = (inner - 1) // 2
    right_pad = inner - 1 - left_pad
    top = f"{_DR}.{'-' * inner}.{_RESET}"
    mid = f"{_DR}({_RESET}{' ' * left_pad}{_W}●{_RESET}{' ' * right_pad}{_DR}){_RESET}"
    bottom = f"{_DR}'{'-' * inner}'{_RESET}"
    return [top, mid, bottom]


def _render_eye(width: int) -> list[str]:
    art = _build_eye_art()
    art_width = len(art[0]) - len(_DR) - len(_RESET)  # longueur visible (sans codes ANSI)
    margin = max(0, (width - art_width) // 2)
    pad = " " * margin
    return [f"{pad}{line}" for line in art]


_LOGO_LINES = [
    r" ███████╗██╗   ██╗███████╗███████╗██████╗ ███████╗██████╗ ",
    r" ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗",
    r" █████╗   ╚████╔╝ █████╗  ███████╗██████╔╝█████╗  ██║  ██║",
    r" ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║██╔══██╗██╔══╝  ██║  ██║",
    r" ███████╗   ██║   ███████╗███████║██║  ██║███████╗██████╔╝",
    r" ╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝ ",
    r"      ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗        ",
    r"      ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝        ",
    r"      ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗          ",
    r"      ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝          ",
    r"      ███████║   ██║   ██║  ██║██║██║  ██╗███████╗        ",
    r"      ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝        ",
]


def render_banner() -> str:
    lines = [f"{_R}{line}{_RESET}" for line in _LOGO_LINES]
    width = max(len(l) for l in _LOGO_LINES)
    rule = f"{_DR}{'─' * width}{_RESET}"
    eye_lines = _render_eye(width)
    subtitle = f"{_W}scan{_D} · {_W}analyse{_D} · {_W}extermine{_RESET}"
    tagline = f"{_D}Antivirus offensif cross-platform — Windows · Linux · macOS{_RESET}"
    credit = f"{_D}v{__version__}  {_RESET}{_R}◆{_RESET}{_D}  by {_RESET}{_W}OPEN DOJO SYSTEMS{_RESET}"
    return "\n".join(
        ["", rule, "", *eye_lines, "", *lines, rule, f"     {subtitle}", f"     {tagline}", f"     {credit}", rule, ""]
    )


def _print_finding(finding: FileFinding) -> None:
    color = SEVERITY_COLOR.get(finding.severity, Fore.WHITE)
    print(f"{color}[{finding.severity.upper()}]{Style.RESET_ALL} {finding.path}")
    print(f"    sha256: {finding.sha256}")
    if finding.ioc_match:
        print(f"    {Fore.RED}IOC connu : famille '{finding.ioc_match}'{Style.RESET_ALL}")
    for m in finding.yara_matches:
        print(f"    YARA: {m.rule} (confiance={m.confidence}) — {m.description}")
    for h in finding.heuristics:
        print(f"    Heuristique [{h.severity}]: {h.detail}")
    if finding.quarantined:
        print(f"    {Fore.GREEN}-> mis en quarantaine{Style.RESET_ALL}")
    print()


def cmd_scan(args: argparse.Namespace) -> int:
    scanner = Scanner()
    quarantine_min = args.quarantine if args.quarantine else None

    def progress(path: Path) -> None:
        if args.verbose:
            print(f"  scanning: {path}", file=sys.stderr)

    report = scanner.scan_path(Path(args.path).expanduser(), quarantine_min_severity=quarantine_min, progress_cb=progress)

    print(f"\n{'=' * 60}")
    print(f"Fichiers scannés : {report.scanned_files} | ignorés : {report.skipped_files}")
    print(f"Menaces détectées : {len(report.threats)}")
    print(f"{'=' * 60}\n")

    for finding in report.threats:
        _print_finding(finding)

    if not report.threats:
        print(f"{Fore.GREEN}Aucune menace détectée.{Style.RESET_ALL}")

    return 1 if report.threats else 0


def cmd_persistence(args: argparse.Namespace) -> int:
    entries = check_persistence()
    if not entries:
        print("Aucun point de persistance détecté (ou plateforme non gérée / permissions insuffisantes).")
        return 0
    print(f"{len(entries)} point(s) de persistance trouvé(s) :\n")
    for e in entries:
        print(f"[{e.mechanism}] {e.location}\n    -> {e.value}\n")
    return 0


def cmd_processes(args: argparse.Namespace) -> int:
    findings = list_suspicious_processes()
    if not findings:
        print("Aucun processus suspect détecté.")
        return 0
    print(f"{len(findings)} processus à examiner :\n")
    for f in findings:
        print(f"PID {f.pid} — {f.name}")
        print(f"    exe: {f.exe}")
        print(f"    cmdline: {f.cmdline}")
        if f.connections:
            print(f"    connexions: {', '.join(f.connections)}")
        for r in f.reasons:
            print(f"    raison: {r}")
        print()
    return 0


def cmd_quarantine_list(args: argparse.Namespace) -> int:
    q = Quarantine()
    records = q.list_records()
    if not records:
        print("Quarantaine vide.")
        return 0
    for r in records:
        print(f"[{r.id}] {r.original_path}")
        print(f"    mis en quarantaine le {r.quarantined_at} — raison: {r.reason}")
        print(f"    sha256: {r.sha256}\n")
    return 0


def cmd_quarantine_restore(args: argparse.Namespace) -> int:
    q = Quarantine()
    try:
        dest = q.restore(args.id)
        print(f"Restauré : {dest}")
        return 0
    except (KeyError, OSError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1


def cmd_quarantine_purge(args: argparse.Namespace) -> int:
    q = Quarantine()
    record = q.get(args.id)
    if record is None:
        print(f"Aucun élément en quarantaine avec l'id {args.id}", file=sys.stderr)
        return 1
    if not args.yes:
        confirm = input(
            f"Suppression DÉFINITIVE de '{record.original_path}' (id={args.id}). Confirmer ? [y/N] "
        )
        if confirm.strip().lower() != "y":
            print("Annulé.")
            return 0
    try:
        q.purge(args.id)
    except OSError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    print("Supprimé définitivement.")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    scanner = Scanner()

    def progress(path: Path) -> None:
        if args.verbose:
            print(f"  scanning: {path}", file=sys.stderr)

    print(f"{_D}Scan + quarantaine automatique (niveau >= {args.level}) de {args.path}{_RESET}\n")
    report = scanner.scan_path(Path(args.path).expanduser(), quarantine_min_severity=args.level, progress_cb=progress)

    print(f"\n{'=' * 60}")
    print(f"Fichiers scannés : {report.scanned_files} | ignorés : {report.skipped_files}")
    print(f"Menaces détectées : {len(report.threats)}")
    print(f"{'=' * 60}\n")

    for finding in report.threats:
        _print_finding(finding)

    quarantined = [f for f in report.threats if f.quarantined]
    not_quarantined = [f for f in report.threats if not f.quarantined]

    if quarantined:
        print(f"{Fore.GREEN}{len(quarantined)} fichier(s) nettoyé(s) (mis en quarantaine).{_RESET}")
        print(f"{_D}Pour vérifier / restaurer : eyesredstrike quarantine list{_RESET}")
    if not_quarantined:
        print(
            f"{Fore.YELLOW}{len(not_quarantined)} détection(s) sous le niveau '{args.level}' "
            f"ignorée(s) (non quarantainées).{_RESET}"
        )
    if not report.threats:
        print(f"{Fore.GREEN}Aucune menace détectée — rien à nettoyer.{_RESET}")

    return 1 if report.threats else 0


def cmd_update_iocs(args: argparse.Namespace) -> int:
    from .core.ioc_update import update_from_malwarebazaar

    try:
        added = update_from_malwarebazaar(tags=args.tags)
        print(f"Total : {added} IOCs ajoutés/mis à jour.")
        return 0
    except RuntimeError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1


class _ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Formatter qui garde la mise en forme manuelle des epilogues (exemples colorés)."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=32, width=100)


def _section(title: str) -> str:
    return f"\n{_W}{title}{_RESET}\n{_D}{'─' * len(title)}{_RESET}"


TOP_EPILOG = (
    _section("WORKFLOW COMPLET : scanner → quarantaine → nettoyer/restaurer")
    + f"""
  {_D}1. Scanner sans rien toucher (rapport seul){_RESET}
  {_W}eyesredstrike scan ~/Downloads{_RESET}

  {_D}2. Mettre en quarantaine ce qui est détecté (réversible, rien n'est supprimé){_RESET}
  {_W}eyesredstrike scan ~/Downloads --quarantine{_RESET}
  {_W}eyesredstrike clean ~/Downloads{_RESET}          {_D}# raccourci = scan + quarantaine en une commande{_RESET}

  {_D}3a. Un fichier mis en quarantaine était un faux positif -> le restaurer{_RESET}
  {_W}eyesredstrike quarantine list{_RESET}
  {_W}eyesredstrike quarantine restore a1b2c3d4e5f6{_RESET}

  {_D}3b. Confirmé malveillant -> suppression définitive et irréversible{_RESET}
  {_W}eyesredstrike quarantine purge a1b2c3d4e5f6{_RESET}
  {_W}eyesredstrike quarantine purge a1b2c3d4e5f6 --yes{_RESET}   {_D}# sans confirmation (scripts/CI){_RESET}
"""
    + _section("AUTRES COMMANDES UTILES")
    + f"""
  {_D}# Vérifier les points de démarrage (registry/cron/systemd/launchd){_RESET}
  {_W}eyesredstrike persistence{_RESET}

  {_D}# Vérifier les processus avec connexions réseau suspectes{_RESET}
  {_W}eyesredstrike processes{_RESET}
"""
    + _section("NIVEAUX DE SÉVÉRITÉ")
    + f"""
  {SEVERITY_COLOR['high']}HIGH{_RESET}    hash IOC connu ou pattern YARA à haute confiance (reverse shell, webshell, ransomware...)
  {SEVERITY_COLOR['medium']}MEDIUM{_RESET}  pattern YARA à confiance moyenne ou heuristique sur binaire (packing + API sensible)
  {SEVERITY_COLOR['low']}LOW{_RESET}     signal faible à corréler (entropie élevée, 1 pattern isolé) — souvent un faux positif
"""
    + f"\n{_D}Documentation complète : voir README.md — projet {_RESET}{_W}Open Dojo Systems{_RESET}\n"
)

SCAN_EPILOG = f"""{_section("EXEMPLES")}
  {_D}# Scan simple, rapport uniquement{_RESET}
  {_W}eyesredstrike scan ~/Downloads{_RESET}

  {_D}# Scan verbeux (affiche chaque fichier analysé){_RESET}
  {_W}eyesredstrike scan ~/Downloads -v{_RESET}

  {_D}# Scan + quarantaine auto dès qu'une menace atteint le niveau "medium"{_RESET}
  {_W}eyesredstrike scan ~/Downloads --quarantine{_RESET}

  {_D}# Quarantaine uniquement les détections HIGH (IOC connu / pattern critique){_RESET}
  {_W}eyesredstrike scan ~/Downloads --quarantine high{_RESET}

  {_D}# Scanner un seul fichier{_RESET}
  {_W}eyesredstrike scan ~/Downloads/suspect.exe{_RESET}

{_D}Le code de sortie est 1 si une menace est détectée, 0 sinon (utilisable en CI/script).{_RESET}
"""

PERSISTENCE_EPILOG = f"""{_section("CE QUI EST VÉRIFIÉ")}
  {_W}Windows{_RESET}  clés registry HKCU/HKLM ...\\CurrentVersion\\Run et RunOnce
  {_W}Linux{_RESET}    /etc/crontab, /etc/cron.d, crontab utilisateur, services systemd, /etc/ld.so.preload
  {_W}macOS{_RESET}    LaunchAgents/LaunchDaemons (plist) et login items (System Events)

{_D}Un point de persistance n'est pas forcément malveillant — beaucoup d'apps légitimes
(mises à jour auto, launchers de jeux) s'enregistrent aussi. À vérifier au cas par cas.{_RESET}
"""

PROCESSES_EPILOG = f"""{_section("CE QUI EST VÉRIFIÉ")}
  - Processus dont le nom correspond à des outils sensibles (nc, mshta.exe, regsvr32.exe...)
  - Arguments de ligne de commande contenant des patterns d'évasion (-EncodedCommand, /dev/tcp/...)
  - Connexions réseau actives établies par le processus

{_D}Nécessite parfois des droits admin/root pour voir tous les processus et leurs connexions.{_RESET}
"""

CLEAN_EPILOG = f"""{_section("EXEMPLES")}
  {_D}# Nettoyage simple : scan + quarantaine tout ce qui est >= medium{_RESET}
  {_W}eyesredstrike clean ~/Downloads{_RESET}

  {_D}# Plus agressif : quarantaine dès le moindre signal faible (LOW inclus){_RESET}
  {_W}eyesredstrike clean ~/Downloads --level low{_RESET}

  {_D}# Plus conservateur : ne quarantaine que les détections certaines (IOC connu, pattern critique){_RESET}
  {_W}eyesredstrike clean ~/Downloads --level high{_RESET}

  {_D}# Nettoyage verbeux d'un dossier complet{_RESET}
  {_W}eyesredstrike clean ~/Downloads --level medium -v{_RESET}

{_D}'clean' = raccourci pour 'scan --quarantine'. Reste réversible : rien n'est supprimé
définitivement. Pour finaliser une suppression après vérification :{_RESET}
  {_W}eyesredstrike quarantine list{_RESET}
  {_W}eyesredstrike quarantine purge <id>{_RESET}
"""

QUARANTINE_EPILOG = f"""{_section("EXEMPLES")}
  {_D}# Voir ce qui est actuellement en quarantaine{_RESET}
  {_W}eyesredstrike quarantine list{_RESET}

  {_D}# Faux positif -> remettre le fichier à son emplacement d'origine{_RESET}
  {_W}eyesredstrike quarantine restore a1b2c3d4e5f6{_RESET}

  {_D}# Confirmé malveillant -> suppression définitive et irréversible (demande confirmation){_RESET}
  {_W}eyesredstrike quarantine purge a1b2c3d4e5f6{_RESET}

  {_D}# Même chose mais sans prompt de confirmation (utile en script/CI){_RESET}
  {_W}eyesredstrike quarantine purge a1b2c3d4e5f6 --yes{_RESET}

  {_D}# Vider toute la quarantaine après audit (à répéter par id, un par un){_RESET}
  {_W}eyesredstrike quarantine list{_RESET}
  {_W}eyesredstrike quarantine purge <id1> --yes && eyesredstrike quarantine purge <id2> --yes{_RESET}

{_D}La quarantaine est réversible : les fichiers sont déplacés + obfusqués (jamais supprimés)
tant que 'purge' n'est pas appelé explicitement. 'purge' est la SEULE opération destructrice.{_RESET}
"""

UPDATE_IOCS_EPILOG = f"""{_section("PRÉREQUIS")}
  Clé API gratuite MalwareBazaar (abuse.ch) : https://bazaar.abuse.ch/api/#get_apikey

  {_W}export ABUSE_CH_API_KEY=votre_cle{_RESET}
  {_W}eyesredstrike update-iocs{_RESET}
  {_W}eyesredstrike update-iocs --tags Wacatac backdoor RAT{_RESET}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eyesredstrike",
        description=(
            f"{_W}EyesRedStrike{_RESET} — scanner cross-platform (Windows/Linux/macOS) ciblant\n"
            f"Wacatac.B!ml, trojans et backdoors. 3 couches de détection (hash IOC + YARA + heuristiques)\n"
            f"et quarantaine réversible. {_D}by Open Dojo Systems{_RESET}"
        ),
        epilog=TOP_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"EyesRedStrike v{__version__} — Open Dojo Systems"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Ne pas afficher la bannière au démarrage")

    sub = parser.add_subparsers(dest="command", required=True, metavar="<commande>")

    p_scan = sub.add_parser(
        "scan",
        help="Scanner un fichier ou répertoire (hash IOC + YARA + heuristiques)",
        description="Scanne récursivement un fichier ou répertoire à travers les 3 couches de détection.",
        epilog=SCAN_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    p_scan.add_argument("path", metavar="CHEMIN", help="Fichier ou répertoire à scanner")
    p_scan.add_argument(
        "--quarantine",
        nargs="?",
        const="medium",
        choices=["low", "medium", "high"],
        default=None,
        metavar="NIVEAU",
        help="Met en quarantaine automatiquement les détections >= NIVEAU (low/medium/high, défaut si omis: medium)",
    )
    p_scan.add_argument("-v", "--verbose", action="store_true", help="Affiche chaque fichier analysé (sur stderr)")
    p_scan.set_defaults(func=cmd_scan)

    p_clean = sub.add_parser(
        "clean",
        help="Raccourci : scan + quarantaine automatique en une commande",
        description="Scanne un chemin et met directement en quarantaine tout ce qui dépasse le niveau choisi.",
        epilog=CLEAN_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    p_clean.add_argument("path", metavar="CHEMIN", help="Fichier ou répertoire à nettoyer")
    p_clean.add_argument(
        "--level",
        choices=["low", "medium", "high"],
        default="medium",
        metavar="NIVEAU",
        help="Quarantaine tout ce qui est >= NIVEAU (low/medium/high, défaut: medium)",
    )
    p_clean.add_argument("-v", "--verbose", action="store_true", help="Affiche chaque fichier analysé (sur stderr)")
    p_clean.set_defaults(func=cmd_clean)

    p_persist = sub.add_parser(
        "persistence",
        help="Lister les points de démarrage/persistance (registry, cron, launchd...)",
        description="Inspecte les mécanismes de persistance connus selon la plateforme courante.",
        epilog=PERSISTENCE_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    p_persist.set_defaults(func=cmd_persistence)

    p_proc = sub.add_parser(
        "processes",
        help="Lister les processus et connexions réseau suspects",
        description="Inspecte les processus en cours d'exécution et leurs connexions réseau actives.",
        epilog=PROCESSES_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    p_proc.set_defaults(func=cmd_processes)

    p_quar = sub.add_parser(
        "quarantine",
        help="Gérer la quarantaine (lister / restaurer / supprimer définitivement)",
        description="Gère les fichiers mis en quarantaine lors d'un scan.",
        epilog=QUARANTINE_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    quar_sub = p_quar.add_subparsers(dest="quarantine_command", required=True, metavar="<action>")

    p_quar_list = quar_sub.add_parser("list", help="Lister les éléments actuellement en quarantaine")
    p_quar_list.set_defaults(func=cmd_quarantine_list)

    p_quar_restore = quar_sub.add_parser("restore", help="Restaurer un élément à son emplacement d'origine")
    p_quar_restore.add_argument("id", metavar="ID", help="Identifiant affiché par 'quarantine list'")
    p_quar_restore.set_defaults(func=cmd_quarantine_restore)

    p_quar_purge = quar_sub.add_parser("purge", help="Supprimer DÉFINITIVEMENT un élément (irréversible)")
    p_quar_purge.add_argument("id", metavar="ID", help="Identifiant affiché par 'quarantine list'")
    p_quar_purge.add_argument("-y", "--yes", action="store_true", help="Ne pas demander de confirmation")
    p_quar_purge.set_defaults(func=cmd_quarantine_purge)

    p_update = sub.add_parser(
        "update-iocs",
        help="Mettre à jour la base de hashs IOC depuis MalwareBazaar (abuse.ch)",
        description="Récupère les derniers hashs SHA-256 connus depuis l'API publique MalwareBazaar.",
        epilog=UPDATE_IOCS_EPILOG,
        formatter_class=_ColorHelpFormatter,
    )
    p_update.add_argument(
        "--tags", nargs="*", default=None, metavar="TAG",
        help="Tags MalwareBazaar à synchroniser (défaut: Wacatac trojan backdoor RAT)",
    )
    p_update.set_defaults(func=cmd_update_iocs)

    return parser


MENU_ITEMS = [
    ("1", "Scanner un dossier/fichier (rapport seul)"),
    ("2", "Nettoyer (scan + quarantaine automatique)"),
    ("3", "Vérifier les points de persistance (registry/cron/launchd)"),
    ("4", "Vérifier les processus/connexions suspects"),
    ("5", "Quarantaine : lister"),
    ("6", "Quarantaine : restaurer un fichier"),
    ("7", "Quarantaine : supprimer définitivement (purge)"),
    ("8", "Mettre à jour la base d'IOCs (MalwareBazaar)"),
    ("0", "Quitter"),
]


def _ask(prompt_text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{_W}{prompt_text}{_RESET}{_D}{suffix}{_RESET} : ").strip()
    return value or (default or "")


def _print_menu() -> None:
    print(_section("MENU PRINCIPAL"))
    for key, label in MENU_ITEMS:
        print(f"  {_R}{key}{_RESET}  {label}")
    print()


def _pause_and_return() -> bool:
    """Retourne True pour revenir au menu, False pour quitter."""
    print()
    try:
        choice = input(f"{_D}Entrée pour revenir au menu principal, 'q' pour quitter{_RESET} : ").strip().lower()
    except EOFError:
        return False
    return choice != "q"


def run_interactive_menu() -> int:
    while True:
        _print_menu()
        try:
            choice = input(f"{_W}Choix{_RESET} : ").strip()
        except EOFError:
            print(f"\n{_D}Entrée standard fermée — arrêt.{_RESET}")
            return 0

        if choice in ("0", "q", "quit", "exit"):
            print(f"{_D}À bientôt.{_RESET}")
            return 0

        try:
            if choice == "1":
                path = _ask("Chemin à scanner", "~/Downloads")
                verbose = _ask("Mode verbeux ? (o/N)", "N").lower().startswith("o")
                cmd_scan(Namespace(path=Path(path).expanduser(), quarantine=None, verbose=verbose))

            elif choice == "2":
                path = _ask("Chemin à nettoyer", "~/Downloads")
                level = _ask("Niveau minimum (low/medium/high)", "medium")
                verbose = _ask("Mode verbeux ? (o/N)", "N").lower().startswith("o")
                cmd_clean(Namespace(path=Path(path).expanduser(), level=level, verbose=verbose))

            elif choice == "3":
                cmd_persistence(Namespace())

            elif choice == "4":
                cmd_processes(Namespace())

            elif choice == "5":
                cmd_quarantine_list(Namespace())

            elif choice == "6":
                qid = _ask("ID à restaurer (voir option 5)")
                if qid:
                    cmd_quarantine_restore(Namespace(id=qid))

            elif choice == "7":
                qid = _ask("ID à purger définitivement (voir option 5)")
                if qid:
                    skip_confirm = _ask("Confirmer sans re-demander ? (o/N)", "N").lower().startswith("o")
                    cmd_quarantine_purge(Namespace(id=qid, yes=skip_confirm))

            elif choice == "8":
                tags_raw = _ask("Tags MalwareBazaar (séparés par des espaces, vide = défaut)", "")
                tags = tags_raw.split() if tags_raw else None
                cmd_update_iocs(Namespace(tags=tags))

            else:
                print(f"{Fore.YELLOW}Choix invalide : '{choice}'{_RESET}")

        except (KeyboardInterrupt,):
            print()
        except Exception as e:  # évite qu'une erreur inattendue ne tue la session interactive
            print(f"{Fore.RED}Erreur : {e}{_RESET}", file=sys.stderr)

        if not _pause_and_return():
            print(f"{_D}À bientôt.{_RESET}")
            return 0


def _ensure_utf8_stdio() -> None:
    """Sur les vieilles consoles Windows (cmd.exe legacy, code page ANSI), stdout peut
    refuser les caractères Unicode du logo/bannière et planter avec UnicodeEncodeError.
    On force UTF-8 avec remplacement silencieux plutôt que de laisser planter le script."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdio()
    colorama_init()
    if argv is None:
        argv = sys.argv[1:]
    show_banner = sys.stdout.isatty() and "-q" not in argv and "--quiet" not in argv
    if show_banner:
        print(render_banner())

    parser = build_parser()

    if not argv:
        return run_interactive_menu()

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
