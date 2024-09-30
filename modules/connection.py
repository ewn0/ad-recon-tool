# -*- coding: utf-8 -*-


import sys
from ldap3 import (
from ldap3.core.exceptions import (


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
    pass

def creer_connexion(
    pass


















