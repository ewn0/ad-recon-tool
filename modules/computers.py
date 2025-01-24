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

        os_nom = str(entree.operatingSystem) if entree.operatingSystem else "Inconnu"

        donnees = {
            "nom": str(entree.cn),
            "os": os_nom,
            "version": str(entree.operatingSystemVersion) if entree.operatingSystemVersion else "N/A",
            "dns": str(entree.dNSHostName) if entree.dNSHostName else "N/A",
            "derniere_connexion": date_str,
            "risque": "CRITIQUE" if any(eol in os_nom for eol in [
                "Windows XP", "Windows Server 2003", "Windows Server 2000"
            ]) else "ELEVÉ",
        }
        resultats.append(donnees)
        lignes_tableau.append([
            donnees["nom"],
            donnees["os"],
            donnees["version"],
            donnees["derniere_connexion"],
            donnees["risque"],
        ])

    afficher_tableau(
        titre="⚠  Machines avec OS obsolète (End of Life)",
        en_tetes=["Nom machine", "Système d'exploitation", "Version", "Dernière connexion", "Niveau de risque"],
        lignes=lignes_tableau,
    )

    if resultats:
        print(
            "\n  [!] ATTENTION : Ces machines ne reçoivent plus les mises à jour de sécurité.\n"
            "      → Planifier une migration ou isolation réseau en urgence."
        )

    return resultats


# ─────────────────────────────────────────────────────────────────────────────
# 3. MACHINES INACTIVES
# ─────────────────────────────────────────────────────────────────────────────

def lister_machines_inactives(
    connexion: Connection,
    domaine: str,
    seuil_jours: int = 90,
) -> list[dict]:
    """
    Identifie les machines du domaine dont la dernière connexion au contrôleur
    de domaine remonte à plus de N jours. Une machine inactive depuis longtemps
    peut indiquer :
      - Un poste hors service / décommissionné mais toujours dans l'AD
      - Un poste non géré (laptops oubliés, VMs dormantes)
      - Un poste sans GPO appliquées (risque de dérive de configuration)

    Args:
        connexion   (Connection) : Objet de connexion LDAP actif.
        domaine     (str)        : Nom de domaine FQDN.
        seuil_jours (int)        : Nombre de jours d'inactivité (défaut : 90).

    Returns:
        list[dict]: Liste des machines inactives.
    """
    print(f"\n[*] Recherche des machines inactives depuis plus de {seuil_jours} jours...")

    base_dn = construire_base_dn(domaine)

    # Calcul de la date limite convertie en FILETIME
    date_limite = datetime.now(tz=timezone.utc) - timedelta(days=seuil_jours)
    filetime_limite = int((date_limite.timestamp() + EPOCH_DIFF_SECONDES) * 10_000_000)

    # Filtre : machines actives dont la dernière connexion est antérieure à la limite
    filtre = (
        f"(&(objectClass=computer)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # Actives uniquement
        f"(lastLogonTimestamp<={filetime_limite}))"
    )

    attributs = [
        "cn",
        "operatingSystem",
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
        print(f"[✘] Erreur lors de la recherche des machines inactives : {erreur}")
        return []

    resultats = []
    lignes_tableau = []

    for entree in connexion.entries:
        ft = entree.lastLogonTimestamp.value
        derniere_co = filetime_vers_datetime(ft) if ft else None

        if derniere_co:
            jours_inactif = (datetime.now(tz=timezone.utc) - derniere_co).days
            date_str = derniere_co.strftime("%d/%m/%Y")
        else:
            jours_inactif = "?"
            date_str = "Jamais"

        donnees = {
            "nom": str(entree.cn),
            "os": str(entree.operatingSystem) if entree.operatingSystem else "Inconnu",
            "dns": str(entree.dNSHostName) if entree.dNSHostName else "N/A",
            "derniere_connexion": date_str,
            "jours_inactif": jours_inactif,
        }
        resultats.append(donnees)
        lignes_tableau.append([
            donnees["nom"],
            donnees["os"],
            donnees["derniere_connexion"],
            str(donnees["jours_inactif"]),
        ])

    afficher_tableau(
        titre=f"Machines inactives (> {seuil_jours} jours)",
        en_tetes=["Nom machine", "Système d'exploitation", "Dernière connexion", "Jours inactif"],
        lignes=lignes_tableau,
    )

    if resultats:
        print(
            "\n  [ℹ] Recommandation : Vérifier si ces machines sont encore utilisées.\n"
            "      Si non : désactiver puis supprimer le compte ordinateur de l'AD."
        )

    return resultats
