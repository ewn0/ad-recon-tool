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

