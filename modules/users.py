# -*- coding: utf-8 -*-
"""
modules/users.py — Fonctions d'audit des comptes utilisateurs Active Directory.

Ce module implémente plusieurs vérifications de sécurité orientées Blue Team :
  - Détection des comptes inactifs depuis N jours
  - Détection des mots de passe configurés pour ne jamais expirer
  - Inventaire des comptes membres de groupes privilégiés
  - Détection de comptes désactivés encore membres de groupes actifs
"""

from datetime import datetime, timedelta, timezone
from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPException

from modules.connection import construire_base_dn


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES LDAP
# ─────────────────────────────────────────────────────────────────────────────

# Filtre de base pour cibler uniquement les comptes utilisateurs (pas les machines)
FILTRE_UTILISATEURS = (
    "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))"
)

# Filtre pour les comptes actifs uniquement
FILTRE_UTILISATEURS_ACTIFS = (
    "(&(objectCategory=person)(objectClass=user)"
    "(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)

# Bit de flag userAccountControl : mot de passe n'expire jamais (0x10000 = 65536)
FLAG_MDP_PERMANENT = 65536

# Bit de flag userAccountControl : compte désactivé (0x0002 = 2)
FLAG_COMPTE_DESACTIVE = 2

# Groupes privilégiés AD standard à surveiller
GROUPES_PRIVILEGIES = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Group Policy Creator Owners",
    "Remote Desktop Users",
    "DNSAdmins",
]

# Décalage Windows FILETIME : Windows compte depuis le 01/01/1601
# Python depuis le 01/01/1970. Différence en secondes.
EPOCH_DIFF_SECONDES = 11644473600


# ─────────────────────────────────────────────────────────────────────────────
# UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

def filetime_vers_datetime(filetime) -> datetime | None:
    """
    Normalise une valeur de timestamp issue d'Active Directory en objet datetime.

    Avec ldap3 en mode SYNC, les attributs de date sont automatiquement
    convertis en datetime Python. Cette fonction gère les deux cas :
      - datetime  : déjà converti par ldap3, on s'assure juste qu'il est en UTC.
      - int       : FILETIME brut (intervalles de 100ns depuis le 01/01/1601),
                    converti manuellement.

    Args:
        filetime: Valeur datetime ou entier FILETIME issue d'Active Directory.

    Returns:
        datetime | None: Date/heure en UTC, ou None si valeur invalide/nulle.
    """
    if filetime is None:
        return None

    # ── Cas 1 : ldap3 SYNC a déjà converti en datetime ───────────────────
    if isinstance(filetime, datetime):
        # S'assurer que le datetime est bien timezone-aware (UTC)
        if filetime.tzinfo is None:
            return filetime.replace(tzinfo=timezone.utc)
        return filetime

    # ── Cas 2 : entier FILETIME brut (100ns depuis 01/01/1601) ───────────
    if isinstance(filetime, int):
        if filetime in (0, 9223372036854775807):
            # 0 = jamais connecté / 9223372036854775807 = "jamais" en AD
            return None
        try:
            timestamp_unix = (filetime / 10_000_000) - EPOCH_DIFF_SECONDES
            return datetime.fromtimestamp(timestamp_unix, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    return None


def afficher_tableau(titre: str, en_tetes: list[str], lignes: list[list], couleur: str = "") -> None:
    """
    Affiche un tableau formaté dans la console avec des séparateurs.

    Args:
        titre    (str)         : Titre du tableau.
        en_tetes (list[str])   : Liste des noms de colonnes.
        lignes   (list[list])  : Liste des lignes de données.
        couleur  (str)         : Préfixe de couleur ANSI (optionnel).
    """
    if not lignes:
        print(f"\n  [✓] {titre} : Aucun résultat trouvé.")
        return

    print(f"\n  ┌─── {titre} ({len(lignes)} résultat(s)) ───")

    # Calcul de la largeur de chaque colonne
    largeurs = [len(h) for h in en_tetes]
    for ligne in lignes:
        for i, cellule in enumerate(ligne):
            if i < len(largeurs):
                largeurs[i] = max(largeurs[i], len(str(cellule)))

    # Ligne d'en-tête
    sep = "  │ " + " │ ".join("─" * l for l in largeurs) + " │"
    ent = "  │ " + " │ ".join(h.ljust(largeurs[i]) for i, h in enumerate(en_tetes)) + " │"
    print(sep)
    print(ent)
    print(sep)

    # Lignes de données
    for ligne in lignes:
        contenu = "  │ " + " │ ".join(
            str(cellule).ljust(largeurs[i]) for i, cellule in enumerate(ligne)
        ) + " │"
        print(contenu)

    print(sep)


# ─────────────────────────────────────────────────────────────────────────────
# 1. UTILISATEURS INACTIFS
# ─────────────────────────────────────────────────────────────────────────────

def lister_utilisateurs_inactifs(
    connexion: Connection,
    domaine: str,
    seuil_jours: int = 90,
) -> list[dict]:
    """
    Recherche les comptes utilisateurs actifs dont la dernière connexion
    remonte à plus de N jours. Un compte inactif prolongé peut indiquer
    un compte oublié / orphelin, cible potentielle d'attaque.

    Args:
        connexion   (Connection) : Objet de connexion LDAP actif.
        domaine     (str)        : Nom de domaine FQDN.
        seuil_jours (int)        : Nombre de jours d'inactivité (défaut : 90).

    Returns:
        list[dict]: Liste des comptes inactifs avec leurs attributs.
    """
    print(f"\n[*] Recherche des utilisateurs inactifs depuis plus de {seuil_jours} jours...")

    base_dn = construire_base_dn(domaine)

    # Calcul de la date limite en FILETIME Windows
    date_limite = datetime.now(tz=timezone.utc) - timedelta(days=seuil_jours)
    # Conversion en FILETIME (intervalles de 100ns depuis 01/01/1601)
    filetime_limite = int((date_limite.timestamp() + EPOCH_DIFF_SECONDES) * 10_000_000)

    # Filtre LDAP : comptes actifs dont la dernière connexion est antérieure à la limite
    filtre = (
        f"(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # Comptes non désactivés
        f"(lastLogonTimestamp<={filetime_limite}))"
    )

    attributs = ["sAMAccountName", "displayName", "lastLogonTimestamp", "mail", "department"]

    try:
        connexion.search(
            search_base=base_dn,
            search_filter=filtre,
            search_scope=SUBTREE,
            attributes=attributs,
        )
    except LDAPException as erreur:
        print(f"[✘] Erreur lors de la recherche LDAP (inactifs) : {erreur}")
        return []

    resultats = []
    lignes_tableau = []

    for entree in connexion.entries:
        # Conversion de la date de dernière connexion
        filetime_brut = entree.lastLogonTimestamp.value
        derniere_connexion = filetime_vers_datetime(filetime_brut) if filetime_brut else None

        if derniere_connexion:
            jours_inactif = (datetime.now(tz=timezone.utc) - derniere_connexion).days
            date_str = derniere_connexion.strftime("%d/%m/%Y")
        else:
            jours_inactif = "?"
            date_str = "Jamais connecté"

        donnees = {
            "sam_account": str(entree.sAMAccountName),
            "nom_complet": str(entree.displayName) if entree.displayName else "N/A",
            "derniere_connexion": date_str,
            "jours_inactif": jours_inactif,
            "email": str(entree.mail) if entree.mail else "N/A",
            "departement": str(entree.department) if entree.department else "N/A",
        }
        resultats.append(donnees)
        lignes_tableau.append([
            donnees["sam_account"],
            donnees["nom_complet"],
            donnees["derniere_connexion"],
            str(donnees["jours_inactif"]),
            donnees["departement"],
        ])

    afficher_tableau(
        titre=f"Utilisateurs inactifs (> {seuil_jours} jours)",
        en_tetes=["Compte", "Nom complet", "Dernière connexion", "Jours inactif", "Département"],
        lignes=lignes_tableau,
    )

    return resultats


# ─────────────────────────────────────────────────────────────────────────────
# 2. MOTS DE PASSE N'EXPIRANT JAMAIS
# ─────────────────────────────────────────────────────────────────────────────

def lister_utilisateurs_mdp_permanent(
    connexion: Connection,
    domaine: str,
) -> list[dict]:
    """
    Identifie les comptes dont le mot de passe est configuré pour
    ne jamais expirer. Ce paramètre, souvent mal géré, représente un risque
    de sécurité si un compte est compromis (le mot de passe ne sera jamais
    forcé à changer).

    Le flag userAccountControl 0x10000 (65536) indique "DONT_EXPIRE_PASSWD".

    Args:
        connexion (Connection) : Objet de connexion LDAP actif.
        domaine   (str)        : Nom de domaine FQDN.

    Returns:
        list[dict]: Liste des comptes avec MDP permanent.
    """
    print("\n[*] Recherche des comptes avec mot de passe permanent (ne expire jamais)...")

    base_dn = construire_base_dn(domaine)

    # Filtre LDAP avec flag bitwise pour DONT_EXPIRE_PASSWD
    filtre = (
        "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536))"
    )

    attributs = ["sAMAccountName", "displayName", "pwdLastSet", "userAccountControl", "department"]

    try:
        connexion.search(
            search_base=base_dn,
            search_filter=filtre,
            search_scope=SUBTREE,
            attributes=attributs,
        )
    except LDAPException as erreur:
        print(f"[✘] Erreur lors de la recherche LDAP (MDP permanent) : {erreur}")
        return []

    resultats = []
    lignes_tableau = []

    for entree in connexion.entries:
        # Conversion de la date du dernier changement de mot de passe
        pwd_last_set = entree.pwdLastSet.value
        date_mdp = filetime_vers_datetime(pwd_last_set) if pwd_last_set else None
        date_str = date_mdp.strftime("%d/%m/%Y") if date_mdp else "Jamais changé"

        # Vérification si le compte est désactivé
        uac = int(entree.userAccountControl.value) if entree.userAccountControl else 0
        est_desactive = bool(uac & FLAG_COMPTE_DESACTIVE)

        donnees = {
            "sam_account": str(entree.sAMAccountName),
            "nom_complet": str(entree.displayName) if entree.displayName else "N/A",
            "dernier_changement_mdp": date_str,
            "est_desactive": est_desactive,
            "departement": str(entree.department) if entree.department else "N/A",
        }
        resultats.append(donnees)
        lignes_tableau.append([
            donnees["sam_account"],
            donnees["nom_complet"],
            donnees["dernier_changement_mdp"],
            "Oui ⚠" if est_desactive else "Non",
            donnees["departement"],
        ])

    afficher_tableau(
        titre="Comptes avec MDP permanent (DONT_EXPIRE_PASSWD)",
        en_tetes=["Compte", "Nom complet", "Dernier changement MDP", "Désactivé", "Département"],
        lignes=lignes_tableau,
    )

    return resultats


# ─────────────────────────────────────────────────────────────────────────────
# 3. COMPTES PRIVILÉGIÉS
# ─────────────────────────────────────────────────────────────────────────────

def lister_comptes_privilegies(
    connexion: Connection,
    domaine: str,
) -> dict[str, list]:
    """
    Liste les membres des groupes privilégiés sensibles d'Active Directory.
    La surveillance des groupes privilégiés est une pratique fondamentale
    du SOC (détection d'escalade de privilèges, comptes de service excessifs).

    Args:
        connexion (Connection) : Objet de connexion LDAP actif.
        domaine   (str)        : Nom de domaine FQDN.

    Returns:
        dict[str, list]: Dictionnaire {nom_groupe: [liste des membres]}.
    """
    print("\n[*] Inventaire des membres des groupes privilégiés...")

    base_dn = construire_base_dn(domaine)
    rapport_groupes = {}

    for nom_groupe in GROUPES_PRIVILEGIES:
        # Recherche du groupe par son nom
        filtre_groupe = f"(&(objectClass=group)(sAMAccountName={nom_groupe}))"

        try:
            connexion.search(
                search_base=base_dn,
                search_filter=filtre_groupe,
                search_scope=SUBTREE,
                attributes=["member", "distinguishedName"],
            )
        except LDAPException as erreur:
            print(f"  [!] Erreur lors de la recherche du groupe '{nom_groupe}' : {erreur}")
            continue

        if not connexion.entries:
            # Le groupe n'existe pas dans cet AD (certains groupes sont optionnels)
            continue

        membres_bruts = connexion.entries[0].member.values if connexion.entries[0].member else []
        membres = []

        for dn_membre in membres_bruts:
            # Extraction du CN (Common Name) depuis le Distinguished Name
            # Format DN : "CN=Prénom Nom,OU=...,DC=..."
            try:
                cn = dn_membre.split(",")[0].replace("CN=", "").strip()
            except (IndexError, AttributeError):
                cn = str(dn_membre)

            membres.append(cn)

        rapport_groupes[nom_groupe] = membres

        # Affichage du groupe et de ses membres
        print(f"\n  ┌─── Groupe : {nom_groupe} ({len(membres)} membre(s))")
        if membres:
            for m in membres:
                print(f"  │   ├── {m}")
        else:
            print("  │   └── (aucun membre direct)")
        print("  └" + "─" * 50)

    return rapport_groupes


# ─────────────────────────────────────────────────────────────────────────────
# 4. COMPTES DÉSACTIVÉS ENCORE DANS DES GROUPES
# ─────────────────────────────────────────────────────────────────────────────

def lister_comptes_desactives_actifs(
    connexion: Connection,
    domaine: str,
) -> list[dict]:
    """
    Identifie les comptes désactivés qui sont encore membres de groupes AD.
    Ce phénomène est fréquent lors de départs non gérés (offboarding).
    Un compte désactivé avec des appartenances de groupes peut représenter
    un risque si le compte est réactivé par erreur ou malveillance.

    Args:
        connexion (Connection) : Objet de connexion LDAP actif.
        domaine   (str)        : Nom de domaine FQDN.

    Returns:
        list[dict]: Liste des comptes désactivés avec leurs groupes.
    """
    print("\n[*] Recherche des comptes désactivés encore membres de groupes...")

    base_dn = construire_base_dn(domaine)

    # Filtre : comptes désactivés (userAccountControl bit 2 = ACCOUNTDISABLE)
    filtre = (
        "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=2)"
        "(memberOf=*))"  # Avec au moins une appartenance à un groupe
    )

    attributs = ["sAMAccountName", "displayName", "memberOf", "whenChanged"]

    try:
        connexion.search(
            search_base=base_dn,
            search_filter=filtre,
            search_scope=SUBTREE,
            attributes=attributs,
        )
    except LDAPException as erreur:
        print(f"[✘] Erreur lors de la recherche LDAP (comptes désactivés) : {erreur}")
        return []
