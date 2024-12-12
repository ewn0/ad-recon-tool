# -*- coding: utf-8 -*-
"""
modules/connection.py — Gestion de la connexion LDAP sécurisée au contrôleur
de domaine Active Directory.

Ce module centralise la logique de connexion afin de :
  - Ne jamais exposer les identifiants dans le code source.
  - Gérer proprement les erreurs réseau et d'authentification.
  - Fournir une instance de connexion réutilisable par les autres modules.
"""

import sys
from ldap3 import (
    Server,
    Connection,
    ALL,
    NTLM,
    SUBTREE,
    SYNC,
)
from ldap3.core.exceptions import (
    LDAPException,
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPSocketSendError,
    LDAPInvalidCredentialsResult,
)


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

# Délai d'attente de connexion en secondes
TIMEOUT_CONNEXION = 10

# Port LDAP standard
PORT_LDAP = 389

# Port LDAPS (LDAP over SSL)
PORT_LDAPS = 636


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUCTION DU DN DE BASE (Base Distinguished Name)
# ─────────────────────────────────────────────────────────────────────────────

def construire_base_dn(domaine: str) -> str:
    """
    Convertit un nom de domaine FQDN en Base DN LDAP.

    Exemple :
        "lab.local" → "DC=lab,DC=local"
        "ad.entreprise.fr" → "DC=ad,DC=entreprise,DC=fr"

    Args:
        domaine (str): Le nom de domaine complet (ex: "lab.local").

    Returns:
        str: Le Base DN correspondant (ex: "DC=lab,DC=local").
    """
    composantes = domaine.split(".")
    return ",".join(f"DC={c}" for c in composantes)


# ─────────────────────────────────────────────────────────────────────────────
# CRÉATION DE LA CONNEXION LDAP
# ─────────────────────────────────────────────────────────────────────────────

def creer_connexion(
    dc_ip: str,
    domaine: str,
    username: str,
    password: str,
    verbose: bool = False,
) -> Connection | None:
    """
    Établit une connexion LDAP au contrôleur de domaine via l'authentification
    NTLM (compatible avec les environnements Windows Active Directory).

    Args:
        dc_ip    (str)  : Adresse IP ou FQDN du contrôleur de domaine.
        domaine  (str)  : Nom de domaine FQDN (ex: "lab.local").
        username (str)  : Nom d'utilisateur (format : "DOMAINE\\\\utilisateur").
        password (str)  : Mot de passe de l'utilisateur.
        verbose  (bool) : Afficher des informations détaillées si True.

    Returns:
        ldap3.Connection | None: Objet connexion si succès, None sinon.
    """

    print(f"\n[*] Connexion au contrôleur de domaine : {dc_ip}")

    # ── Étape 1 : Définition du serveur LDAP ─────────────────────────────
    try:
        serveur = Server(
            host=dc_ip,
            port=PORT_LDAP,
            get_info=ALL,           # Récupère les informations du schéma AD
            connect_timeout=TIMEOUT_CONNEXION,
        )

        if verbose:
            print(f"    [>] Serveur défini : {dc_ip}:{PORT_LDAP}")

    except LDAPException as erreur:
        print(f"[✘] Erreur lors de la définition du serveur LDAP : {erreur}")
        return None

    # ── Étape 2 : Formatage du nom d'utilisateur ─────────────────────────
    # ldap3 avec NTLM attend le format "DOMAINE\utilisateur"
    # On normalise pour éviter les erreurs de saisie
    domaine_court = domaine.split(".")[0].upper()

    if "\\" in username:
        # L'utilisateur a déjà fourni le format DOMAINE\user
        user_ntlm = username
    else:
        # On préfixe automatiquement avec le nom de domaine court
        user_ntlm = f"{domaine_court}\\{username}"

    if verbose:
        print(f"    [>] Authentification NTLM en tant que : {user_ntlm}")

    # ── Étape 3 : Tentative de connexion ─────────────────────────────────
    try:
        connexion = Connection(
            server=serveur,
            user=user_ntlm,
            password=password,
            authentication=NTLM,
            client_strategy=SYNC,   # SYNC peuple connexion.entries après chaque search()
            auto_bind=True,         # Lance le bind automatiquement
            raise_exceptions=True,  # Lève des exceptions en cas d'erreur
        )

    except LDAPInvalidCredentialsResult as erreur:
        # Le DC a répondu mais les identifiants sont rejetés
        # On parse le sous-code AD dans le message d'erreur pour un diagnostic précis
        message = str(erreur)
        sous_codes_ad = {
            "52e": "Mot de passe incorrect",
            "525": "Compte introuvable dans l'annuaire",
            "530": "Connexion non autorisée à cette heure",
            "531": "Connexion non autorisée depuis ce poste",
            "532": "Mot de passe expiré — changement requis",
            "533": "Compte désactivé",
            "701": "Compte expiré",
            "773": "L'utilisateur doit changer son mot de passe à la prochaine connexion",
            "775": "Compte verrouillé",
        }
        # Extraction du sous-code (ex: "data 52e" dans le message)
        diagnostic = "Identifiants refusés par le contrôleur de domaine"
        for code, libelle in sous_codes_ad.items():
            if f"data {code}" in message:
                diagnostic = f"Code AD {code} — {libelle}"
                break
        print(
            f"\n[✘] Échec d'authentification LDAP : {diagnostic}\n"
            f"    → Compte utilisé : {user_ntlm}\n"
            "    → Vérifiez USERNAME et PASSWORD dans votre fichier .env"
        )
        return None

    except LDAPBindError:
        # Erreur de bind générique (protocole)
        print(
            "\n[✘] Échec d'authentification LDAP.\n"
            "    → Vérifiez le nom d'utilisateur et le mot de passe dans .env.\n"
            "    → Vérifiez que le compte n'est pas verrouillé."
        )
        return None

    except LDAPSocketOpenError:
        # Problème réseau : DC inaccessible ou port fermé
        print(
            f"\n[✘] Impossible de joindre le contrôleur de domaine : {dc_ip}:{PORT_LDAP}\n"
            "    → Vérifiez que la machine est accessible (ping, pare-feu).\n"
            "    → Vérifiez que le service LDAP est actif sur le DC."
        )
        return None

    except LDAPSocketSendError:
        # Connexion interrompue pendant l'envoi
        print(
            "\n[✘] La connexion au DC a été interrompue pendant la communication.\n"
            "    → Vérifiez la stabilité du réseau."
        )
        return None

    except LDAPException as erreur:
