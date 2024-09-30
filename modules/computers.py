# -*- coding: utf-8 -*-



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

# Filtre LDAP pour cibler les machines (comptes ordinateurs)
FILTRE_MACHINES = "(objectClass=computer)"

# Filtre pour les machines actives (non désactivées)
FILTRE_MACHINES_ACTIVES = (


# ─────────────────────────────────────────────────────────────────────────────
# 1. INVENTAIRE COMPLET DES MACHINES
# ─────────────────────────────────────────────────────────────────────────────

def lister_toutes_les_machines(
    pass
















def lister_os_obsoletes(
    pass

















def lister_machines_inactives(
    pass














