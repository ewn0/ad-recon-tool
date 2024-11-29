# -*- coding: utf-8 -*-
"""
modules/computers.py — Fonctions d'audit des machines du domaine Active Directory.

Ce module implémente plusieurs vérifications de sécurité orientées Blue Team :
  - Inventaire complet des machines du domaine
  - Détection des systèmes d'exploitation obsolètes (Windows XP, 7, Server 2003, etc.)
  - Détection des machines inactives depuis N jours

Les OS obsolètes représentent une surface d'attaque critique : ils ne reçoivent
plus les mises à jour de sécurité et sont vulnérables à des exploits connus
(EternalBlue / MS17-010, etc.).
"""

from datetime import datetime, timedelta, timezone
from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPException

from modules.connection import construire_base_dn
from modules.users import filetime_vers_datetime, afficher_tableau, EPOCH_DIFF_SECONDES


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

# Liste des OS considérés comme obsolètes (plus supportés par Microsoft)
# Source : https://learn.microsoft.com/en-us/lifecycle/
OS_OBSOLETES = [
    "Windows XP",
    "Windows Vista",
    "Windows 7",
    "Windows 8",
    "Windows 8.1",
    "Windows Server 2000",
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2012",         # Fin de support : octobre 2023
    "Windows Server 2012 R2",      # Fin de support : octobre 2023
]

# Filtre LDAP pour cibler les machines (comptes ordinateurs)
FILTRE_MACHINES = "(objectClass=computer)"

# Filtre pour les machines actives (non désactivées)
FILTRE_MACHINES_ACTIVES = (
    "(&(objectClass=computer)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. INVENTAIRE COMPLET DES MACHINES
# ─────────────────────────────────────────────────────────────────────────────

def lister_toutes_les_machines(
    connexion: Connection,
    domaine: str,
) -> list[dict]:
    """
    Effectue un inventaire complet de toutes les machines (postes et serveurs)
    enregistrées dans le domaine Active Directory.

    Args:
        connexion (Connection) : Objet de connexion LDAP actif.
        domaine   (str)        : Nom de domaine FQDN.

    Returns:
        list[dict]: Liste de toutes les machines avec leurs attributs.
    """
    print("\n[*] Inventaire complet des machines du domaine...")

    base_dn = construire_base_dn(domaine)

    attributs = [
        "cn",                   # Nom de la machine
        "operatingSystem",      # Système d'exploitation
        "operatingSystemVersion",  # Version de l'OS
        "lastLogonTimestamp",   # Dernière connexion au domaine
        "dNSHostName",          # Nom DNS complet
        "description",          # Description (souvent utilisée pour le rôle)
        "userAccountControl",   # Flags du compte
        "whenCreated",          # Date de création dans l'AD
    ]

    try:
        connexion.search(
            search_base=base_dn,
            search_filter=FILTRE_MACHINES,
            search_scope=SUBTREE,
            attributes=attributs,
        )
    except LDAPException as erreur:
        print(f"[✘] Erreur lors de l'inventaire des machines : {erreur}")
        return []

    resultats = []
    lignes_tableau = []

    for entree in connexion.entries:
        # Vérification du statut (actif/désactivé)
        uac = int(entree.userAccountControl.value) if entree.userAccountControl else 0
        est_desactive = bool(uac & 2)

        # Conversion de la dernière connexion
        ft = entree.lastLogonTimestamp.value
        derniere_co = filetime_vers_datetime(ft) if ft else None
        date_str = derniere_co.strftime("%d/%m/%Y") if derniere_co else "Jamais"

        os_nom = str(entree.operatingSystem) if entree.operatingSystem else "Inconnu"
        os_ver = str(entree.operatingSystemVersion) if entree.operatingSystemVersion else "N/A"

        donnees = {
            "nom": str(entree.cn),
            "os": os_nom,
            "version": os_ver,
            "dns": str(entree.dNSHostName) if entree.dNSHostName else "N/A",
            "derniere_connexion": date_str,
            "est_desactive": est_desactive,
            "description": str(entree.description) if entree.description else "N/A",
        }
        resultats.append(donnees)
        lignes_tableau.append([
            donnees["nom"],
            donnees["os"],
            donnees["version"],
            donnees["derniere_connexion"],
            "⚠ Désactivé" if est_desactive else "Actif",
        ])

    afficher_tableau(
        titre="Inventaire complet des machines du domaine",
        en_tetes=["Nom machine", "Système d'exploitation", "Version", "Dernière connexion", "Statut"],
        lignes=lignes_tableau,
    )

    print(f"\n  [ℹ] Total : {len(resultats)} machine(s) recensée(s).")

    return resultats


# ─────────────────────────────────────────────────────────────────────────────
# 2. SYSTÈMES D'EXPLOITATION OBSOLÈTES
# ─────────────────────────────────────────────────────────────────────────────

def lister_os_obsoletes(
    connexion: Connection,
    domaine: str,
) -> list[dict]:
    """
    Détecte les machines du domaine fonctionnant sous un système d'exploitation
    qui n'est plus supporté par Microsoft (End of Life / EOL).

    Ces machines sont une priorité absolue de remédiation car elles ne
    reçoivent plus les correctifs de sécurité. Elles sont vulnérables à des
    exploits publics souvent intégrés dans des ransomwares (ex: WannaCry via
    EternalBlue sur Windows 7 / Server 2008).

    Args:
        connexion (Connection) : Objet de connexion LDAP actif.
        domaine   (str)        : Nom de domaine FQDN.

    Returns:
        list[dict]: Liste des machines avec un OS EOL.
    """
    print("\n[*] Détection des systèmes d'exploitation obsolètes (EOL)...")
    print(f"    [>] OS surveillés : {', '.join(OS_OBSOLETES)}")

    base_dn = construire_base_dn(domaine)

    # Construction d'un filtre LDAP avec OU logique sur tous les OS obsolètes
    # Chaque OS est testé avec une correspondance partielle via le wildcard *
    filtres_os = "".join(
        f"(operatingSystem=*{os}*)" for os in OS_OBSOLETES
    )
    filtre = f"(&(objectClass=computer)(|{filtres_os}))"

    attributs = [
        "cn",
        "operatingSystem",
        "operatingSystemVersion",
        "lastLogonTimestamp",
        "dNSHostName",
        "description",
    ]

    try:
        connexion.search(
            search_base=base_dn,
            search_filter=filtre,
            search_scope=SUBTREE,
            attributes=attributs,
        )
    except LDAPException as erreur:
        print(f"[✘] Erreur lors de la recherche des OS obsolètes : {erreur}")
        return []

    resultats = []
    lignes_tableau = []

    for entree in connexion.entries:
        ft = entree.lastLogonTimestamp.value
        derniere_co = filetime_vers_datetime(ft) if ft else None
        date_str = derniere_co.strftime("%d/%m/%Y") if derniere_co else "Jamais"

