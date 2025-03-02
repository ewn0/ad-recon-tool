# 🛡️ AD-ENUM — Outil d'Audit Active Directory

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![ldap3](https://img.shields.io/badge/ldap3-2.9%2B-4A90D9?style=for-the-badge&logo=ldap&logoColor=white)
![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-0057B8?style=for-the-badge&logo=shield&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**Outil d'énumération et d'audit de sécurité Active Directory**  
*Conçu pour les équipes Blue Team, les SOC Analysts et les auditeurs en sécurité.*

</div>

---

## 📋 Table des matières

- [Contexte Blue Team](#-contexte-blue-team)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Interprétation des résultats](#-interprétation-des-résultats)
- [Sécurité & Éthique](#-sécurité--éthique)
- [Licence](#-licence)

---

## 🔵 Contexte Blue Team

Active Directory est le cœur névralgique de la plupart des environnements Windows en entreprise. Sa compromission est l'objectif ultime de nombreuses cyberattaques, notamment les ransomwares et les APT (Advanced Persistent Threats).

Ce projet est né d'un constat simple : **un AD mal maintenu est un AD compromis en sursis.**

Les équipes Blue Team et les SOC Analysts ont besoin d'outils d'audit permettant d'identifier rapidement les **dérives de configuration** avant que des acteurs malveillants ne les exploitent :

| Problème détecté | Risque associé | Attaque possible |
|---|---|---|
| Comptes inactifs | Comptes orphelins non surveillés | Mouvement latéral, persistance |
| MDP ne expirant jamais | Credentials potentiellement exposés depuis longtemps | Pass-the-Hash, Credential Stuffing |
| OS obsolètes | Absence de correctifs de sécurité | EternalBlue (MS17-010), WannaCry |
| Comptes privilégiés non maîtrisés | Escalade de privilèges facilitée | DCSync, Golden Ticket |
| Comptes désactivés dans des groupes | Réactivation accidentelle avec accès conservés | Persistence, réactivation malveillante |

---

## ✨ Fonctionnalités

### 👤 Module Utilisateurs (`--users`)
- **Comptes inactifs** : Détection des utilisateurs sans connexion depuis N jours (défaut : 90)
- **Mots de passe permanents** : Identification des comptes avec le flag `DONT_EXPIRE_PASSWD`
- **Comptes privilégiés** : Inventaire des membres des groupes sensibles (Domain Admins, Schema Admins, etc.)
- **Comptes désactivés** : Détection des comptes désactivés encore membres de groupes AD

### 💻 Module Machines (`--computers`)
- **Inventaire complet** : Liste toutes les machines avec leur OS et statut
- **OS obsolètes (EOL)** : Détection des systèmes sans support Microsoft (Windows XP, 7, Server 2008, etc.)
- **Machines inactives** : Identification des postes/serveurs sans connexion depuis N jours

### 📊 Rapports
- **Affichage console** : Résultats formatés en tableaux lisibles
- **Export JSON** : Export complet du rapport avec métadonnées pour intégration SIEM/ticketing

---

## 🏗️ Architecture

```
ad-audit-tool/
│
├── ad_enum.py              ← Point d'entrée (CLI avec argparse)
│
├── modules/
│   ├── __init__.py         ← Package Python
│   ├── connection.py       ← Connexion LDAP sécurisée (NTLM)
│   ├── users.py            ← Audit des comptes utilisateurs
│   └── computers.py        ← Audit des machines du domaine
│
├── .env.example            ← Modèle de configuration (à copier en .env)
├── .gitignore              ← Exclusion des fichiers sensibles
├── requirements.txt        ← Dépendances Python
└── README.md               ← Cette documentation
```

### Schéma de fonctionnement

```
┌─────────────────────────────────────────────────────────────────┐
│                         Poste d'audit                           │
│                                                                 │
│  ┌──────────────┐    ┌─────────────────────────────────────┐   │
│  │   .env       │───▶│         ad_enum.py (CLI)            │   │
│  │  (identif.)  │    │  argparse → sélection des modules   │   │
│  └──────────────┘    └──────────────┬──────────────────────┘   │
│                                     │                           │
│                     ┌───────────────┼──────────────────┐        │
│                     ▼               ▼                  ▼        │
│              ┌────────────┐  ┌──────────────┐  ┌────────────┐  │
│              │connection.py│  │   users.py   │  │computers.py│  │
│              │ LDAP/NTLM  │  │ (utilisateur)│  │ (machines) │  │
│              └─────┬──────┘  └──────┬───────┘  └─────┬──────┘  │
│                    │                │                 │         │
└────────────────────┼────────────────┼─────────────────┼─────────┘
                     │ LDAP:389       │ Requêtes LDAP   │
                     ▼                ▼                 ▼
              ┌──────────────────────────────────────────────┐
              │         Contrôleur de Domaine (DC)           │
              │              Active Directory                 │
              │         LDAP / Authentification NTLM         │
              └──────────────────────────────────────────────┘
                                     │
                                     ▼
              ┌──────────────────────────────────────────────┐
              │              Résultats                        │
              │   Console (tableaux formatés) + JSON export  │
              └──────────────────────────────────────────────┘
```

---

## 📦 Prérequis

| Prérequis | Version | Description |
|---|---|---|
| **Python** | ≥ 3.11 | Requis pour les annotations de type `X \| Y` |
| **Réseau** | — | Accès au DC sur le port **389 (LDAP)** |
| **Compte AD** | — | Compte avec droits de **lecture LDAP** (non-admin suffisant) |

> **⚠️ Important** : Un compte de service dédié avec droits en lecture seule est recommandé.
> N'utilisez **jamais** le compte Administrateur du domaine pour des audits.

---

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-username/ad-audit-tool.git
cd ad-audit-tool
```

### 2. Créer un environnement virtuel (recommandé)

```bash
# Création
python -m venv venv

# Activation (Linux/macOS)
source venv/bin/activate

# Activation (Windows)
venv\Scripts\activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### Copier et renseigner le fichier `.env`

```bash
cp .env.example .env
```

Puis éditer `.env` avec vos valeurs :

```env
DC_IP=192.168.1.10        # IP du Contrôleur de Domaine
DOMAIN=lab.local           # Nom de domaine FQDN
USERNAME=auditeur          # Compte de lecture AD
PASSWORD=VotreMotDePasse   # Mot de passe
```

> **🔒 Sécurité** : Le fichier `.env` est exclu par `.gitignore`. Il ne sera **jamais** publié sur GitHub.

### Compte AD recommandé

Créer un compte dédié dans l'AD avec les droits minimaux :
```
Nom : svc-audit
Groupe : Domain Users (lecture seule)
Droits LDAP : Lecture sur l'ensemble du domaine
MDP : Complexe, expirant régulièrement
```

---

## 🖥️ Usage

### Aide complète

```bash
python ad_enum.py --help
```

### Audit complet (tous les modules)

```bash
python ad_enum.py --all
```

### Audit uniquement les utilisateurs

```bash
python ad_enum.py --users
```

### Audit uniquement les machines

```bash
python ad_enum.py --computers
```

### Combinaisons et options avancées

```bash
# Audit complet avec export JSON
python ad_enum.py --all --export rapport_audit_$(date +%Y%m%d).json

# Modifier le seuil d'inactivité (60 jours au lieu de 90)
python ad_enum.py --users --inactif-jours 60

# Mode verbeux (affiche les détails des requêtes LDAP)
python ad_enum.py --all --verbose

# Audit utilisateurs + export
python ad_enum.py --users --export utilisateurs_risques.json
```

### Exemple de sortie console

```
╔══════════════════════════════════════════════════════════════╗
║          AD-ENUM — Outil d'Audit Active Directory            ║
║                Blue Team / SOC Analyst Tool                  ║
║                       Version 1.0.0                          ║
╚══════════════════════════════════════════════════════════════╝

  [*] Démarrage : 20/04/2026 à 11:15:00
  [*] Domaine cible : lab.local
  [*] Contrôleur de domaine : 192.168.1.10

[*] Connexion au contrôleur de domaine : 192.168.1.10
[✔] Connexion LDAP établie avec succès en tant que : LAB\auditeur

══════════════════════════════════════════════════════════════════
  MODULE : AUDIT DES COMPTES UTILISATEURS
══════════════════════════════════════════════════════════════════

[*] Recherche des utilisateurs inactifs depuis plus de 90 jours...

  ┌─── Utilisateurs inactifs (> 90 jours) (3 résultat(s)) ───
  │ Compte        │ Nom complet      │ Dernière connexion │ Jours │ Département │
  │───────────────│──────────────────│────────────────────│───────│─────────────│
  │ j.dupont      │ Jean Dupont      │ 15/10/2025         │ 186   │ RH          │
  │ m.martin      │ Marie Martin     │ 01/08/2025         │ 261   │ Comptabilité│
  │ svc_backup01  │ Service Backup   │ Jamais connecté    │ ?     │ N/A         │
  └───────────────────────────────────────────────────────────
```

---

## 📊 Interprétation des résultats

### Priorités de remédiation recommandées

| Niveau | Problème | Action recommandée |
|---|---|---|
| 🔴 **CRITIQUE** | OS EOL (XP, Server 2003) | Migration ou isolation réseau immédiate |
| 🔴 **CRITIQUE** | Comptes non-humains dans Domain Admins | Retrait immédiat du groupe |
| 🟠 **ÉLEVÉ** | OS EOL (Win 7, Server 2008/2012) | Planifier migration sous 30 jours |
| 🟠 **ÉLEVÉ** | Comptes inactifs depuis > 180 jours | Désactivation puis suppression |
| 🟡 **MOYEN** | MDP permanent sur comptes actifs | Forcer un changement de MDP |
| 🟡 **MOYEN** | Comptes inactifs depuis > 90 jours | Vérifier avec les managers |
| 🟢 **FAIBLE** | Comptes désactivés dans groupes | Nettoyage lors du prochain cycle |
| 🟢 **FAIBLE** | Machines inactives | Inventaire physique puis décommission |

### Sur le fichier JSON exporté

Le rapport JSON peut être intégré dans un SIEM (Splunk, Elastic), un outil de ticketing (Jira, ServiceNow) ou un tableau de bord de sécurité pour un suivi dans le temps.

Structure du rapport :

```json
{
    "metadata": {
        "domaine": "lab.local",
        "dc_ip": "192.168.1.10",
        "date_audit": "2026-04-20T11:15:00",
        "seuil_inactivite_jours": 90
    },
    "utilisateurs": {
        "inactifs": [...],
        "mdp_permanent": [...],
        "comptes_privilegies": {...},
        "desactives_groupes_actifs": [...]
    },
    "machines": {
        "inventaire_complet": [...],
        "os_obsoletes": [...],
        "inactives": [...]
    }
}
```

---

## 🔒 Sécurité & Éthique

> **⚠️ Avertissement légal**

Cet outil est conçu **exclusivement** pour :
- L'audit de votre propre infrastructure ou d'environnements pour lesquels vous avez une **autorisation écrite explicite**.
- Les laboratoires de test et environnements d'apprentissage.

**Toute utilisation non autorisée sur un système tiers est illégale** (Code pénal français, article 323-1 et suivants).

### Bonnes pratiques intégrées

- ✅ **Aucun secret en dur** : Les identifiants sont chargés depuis des variables d'environnement
- ✅ **Compte à privilèges minimaux** : Lecture seule LDAP, pas besoin de droits admin
- ✅ **`.gitignore` configuré** : Le fichier `.env` est automatiquement exclu des commits
- ✅ **Gestion des erreurs** : Aucune stacktrace brutale exposée à l'utilisateur
- ✅ **Pas d'écriture sur l'AD** : L'outil est 100% en lecture seule

---


---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">

**Développé dans le cadre d'un BUT Informatique — Parcours Cybersécurité**  
*Portfolio Blue Team / SOC Analyst*

[![GitHub](https://img.shields.io/badge/GitHub-Voir%20le%20profil-181717?style=flat-square&logo=github)](https://github.com/ewn0)

</div>
