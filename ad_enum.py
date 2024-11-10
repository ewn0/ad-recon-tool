#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ad_enum.py — Point d'entrée principal de l'outil d'audit Active Directory.

Auteur      : [Votre Nom]
Version     : 1.0.0
Licence     : MIT
Description : Cet outil permet d'effectuer une énumération et un audit de
              sécurité d'un environnement Active Directory via le protocole
              LDAP. Conçu pour les équipes Blue Team et les auditeurs.

Usage :
    python ad_enum.py --all
    python ad_enum.py --users
    python ad_enum.py --computers
    python ad_enum.py --users --computers --export rapport.json
"""

import argparse
import sys
import json
import os
import io
from datetime import datetime
from dotenv import load_dotenv

# ── Fix encodage Windows ──────────────────────────────────────────────────────
# PowerShell utilise CP1252 par défaut, ce qui fait planter les caractères
# Unicode (╔, ✔, ✘, ═...). On force stdout et stderr en UTF-8 au démarrage.
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Import des modules internes
from modules.connection import creer_connexion
from modules.users import (
    lister_utilisateurs_inactifs,
    lister_utilisateurs_mdp_permanent,
    lister_comptes_privilegies,
    lister_comptes_desactives_actifs,
)
from modules.computers import (
    lister_os_obsoletes,
    lister_machines_inactives,
    lister_toutes_les_machines,
)

# Chargement des variables d'environnement depuis le fichier .env
load_dotenv()


# ─────────────────────────────────────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────────────────────────────────────

BANNIERE = r"""
╔══════════════════════════════════════════════════════════════╗
║          AD-ENUM — Outil d'Audit Active Directory            ║
║                Blue Team / SOC Analyst Tool                  ║
║                       Version 1.0.0                          ║
╚══════════════════════════════════════════════════════════════╝
"""


def afficher_banniere():
    """Affiche la bannière de l'outil dans la console."""
    print(BANNIERE)
    print(f"  [*] Démarrage : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}")
    print(f"  [*] Domaine cible : {os.getenv('DOMAIN', 'Non défini')}")
    print(f"  [*] Contrôleur de domaine : {os.getenv('DC_IP', 'Non défini')}")
    print("-" * 65)


# ─────────────────────────────────────────────────────────────────────────────
# GESTION DES ARGUMENTS EN LIGNE DE COMMANDE
# ─────────────────────────────────────────────────────────────────────────────

def construire_parseur() -> argparse.ArgumentParser:
    """
    Construit et retourne le parseur d'arguments CLI.

    Returns:
        argparse.ArgumentParser: Le parseur configuré.
    """
    parseur = argparse.ArgumentParser(
        prog="ad_enum.py",
        description=(
            "Outil d'énumération et d'audit Active Directory — Blue Team"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python ad_enum.py --all\n"
            "  python ad_enum.py --users\n"
            "  python ad_enum.py --computers --export rapport.json\n"
            "  python ad_enum.py --users --computers --export audit.json\n"
        ),
    )

    # ── Groupe : Modules d'audit ──────────────────────────────────────────
    groupe_audit = parseur.add_argument_group("Modules d'audit")
    groupe_audit.add_argument(
        "--all", "-a",
        action="store_true",
        help="Exécuter tous les modules d'audit (utilisateurs + machines)",
    )
    groupe_audit.add_argument(
        "--users", "-u",
        action="store_true",
        help="Audit des comptes utilisateurs (inactifs, MDP permanent, etc.)",
    )
    groupe_audit.add_argument(
        "--computers", "-c",
        action="store_true",
        help="Audit des machines (OS obsolètes, inactives, etc.)",
    )

    # ── Groupe : Options ──────────────────────────────────────────────────
    groupe_options = parseur.add_argument_group("Options")
    groupe_options.add_argument(
        "--export", "-e",
        metavar="FICHIER",
        help="Exporter les résultats au format JSON dans un fichier",
    )
    groupe_options.add_argument(
        "--inactif-jours",
        type=int,
        default=90,
        metavar="JOURS",
        help="Seuil d'inactivité en jours (défaut : 90)",
    )
    groupe_options.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher des informations détaillées sur les requêtes LDAP",
    )

    return parseur


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────────────────────────────────────

def exporter_json(resultats: dict, chemin_fichier: str) -> None:
    """
    Exporte le dictionnaire de résultats dans un fichier JSON.

    Args:
        resultats (dict)       : Données à exporter.
        chemin_fichier (str)   : Chemin du fichier de sortie.
    """
    try:
        with open(chemin_fichier, "w", encoding="utf-8") as f:
            json.dump(resultats, f, ensure_ascii=False, indent=4, default=str)
        print(f"\n[✔] Résultats exportés dans : {chemin_fichier}")
    except IOError as erreur:
        print(f"\n[✘] Impossible d'écrire le fichier d'export : {erreur}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

