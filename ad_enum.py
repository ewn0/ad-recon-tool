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

def main():
    """Fonction principale : parse les arguments, connecte et lance les audits."""

    # ── Affichage de la bannière ──────────────────────────────────────────
    afficher_banniere()

    # ── Parsing des arguments ─────────────────────────────────────────────
    parseur = construire_parseur()
    args = parseur.parse_args()

    # Vérification : au moins un module doit être sélectionné
    if not (args.all or args.users or args.computers):
        parseur.print_help()
        print("\n[!] Erreur : spécifiez au moins un module (--all, --users, --computers).")
        sys.exit(1)

    # ── Récupération des variables d'environnement ────────────────────────
    dc_ip    = os.getenv("DC_IP")
    domaine  = os.getenv("DOMAIN")
    username = os.getenv("AD_USERNAME")  # AD_USERNAME évite le conflit avec la variable système Windows USERNAME
    password = os.getenv("AD_PASSWORD")  # AD_PASSWORD par cohérence

    # Validation de la présence des variables obligatoires
    variables_manquantes = [
        var for var, val in {
            "DC_IP": dc_ip,
            "DOMAIN": domaine,
            "AD_USERNAME": username,
            "AD_PASSWORD": password,
        }.items() if not val
    ]

    if variables_manquantes:
        print(
            f"\n[✘] Variables d'environnement manquantes : "
            f"{', '.join(variables_manquantes)}"
        )
        print("    → Copiez .env.example vers .env et renseignez les valeurs.")
        sys.exit(1)

    # ── Connexion au contrôleur de domaine ────────────────────────────────
    connexion = creer_connexion(dc_ip, domaine, username, password, args.verbose)

    if connexion is None:
        sys.exit(1)

    # ── Initialisation du rapport ─────────────────────────────────────────
    rapport = {
        "metadata": {
            "domaine": domaine,
            "dc_ip": dc_ip,
            "date_audit": datetime.now().isoformat(),
            "seuil_inactivite_jours": args.inactif_jours,
        }
    }

    # ── Module : Utilisateurs ─────────────────────────────────────────────
    if args.all or args.users:
        print("\n\n" + "═" * 65)
        print("  MODULE : AUDIT DES COMPTES UTILISATEURS")
        print("═" * 65)

        rapport["utilisateurs"] = {}

        # Utilisateurs inactifs
        inactifs = lister_utilisateurs_inactifs(connexion, domaine, args.inactif_jours)
        rapport["utilisateurs"]["inactifs"] = inactifs

        # Mots de passe permanents
        mdp_permanent = lister_utilisateurs_mdp_permanent(connexion, domaine)
        rapport["utilisateurs"]["mdp_permanent"] = mdp_permanent

        # Comptes privilégiés
        privilegies = lister_comptes_privilegies(connexion, domaine)
        rapport["utilisateurs"]["comptes_privilegies"] = privilegies

        # Comptes désactivés encore présents dans des groupes actifs
        desactives = lister_comptes_desactives_actifs(connexion, domaine)
        rapport["utilisateurs"]["desactives_groupes_actifs"] = desactives

    # ── Module : Machines ─────────────────────────────────────────────────
    if args.all or args.computers:
        print("\n\n" + "═" * 65)
        print("  MODULE : AUDIT DES POSTES ET SERVEURS")
        print("═" * 65)

        rapport["machines"] = {}

        # Toutes les machines
        toutes = lister_toutes_les_machines(connexion, domaine)
        rapport["machines"]["inventaire_complet"] = toutes

        # OS obsolètes
        obsoletes = lister_os_obsoletes(connexion, domaine)
        rapport["machines"]["os_obsoletes"] = obsoletes

        # Machines inactives
        inactives = lister_machines_inactives(connexion, domaine, args.inactif_jours)
        rapport["machines"]["inactives"] = inactives

    # ── Export JSON (optionnel) ───────────────────────────────────────────
    if args.export:
        exporter_json(rapport, args.export)

    # ── Résumé final ──────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  [✔] Audit terminé avec succès.")
    print("─" * 65 + "\n")


if __name__ == "__main__":
    main()
