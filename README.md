# Mini Projet : Infrastructure Réseau Sécurisée (Zero Trust)

**Réalisé par :** [RGUIBI Mohamed Mouad] [AIT SAID AYOUB]  
**Module :** Sécurité des systèmes informatiques (LSI3 s5)  
**Encadrant :** Pr. Ikram BEN ABDELOUAHAB    
---

## 📋 Description

Ce projet implémente une infrastructure réseau sécurisée simulée sous **Mininet**, respectant les principes du modèle **Zero Trust**.

**Fonctionnalités principales :**

* **Segmentation Stricte :** Zones WAN, LAN (isolé) et DMZ séparées.
* **Pare-feu Stateful :** Filtrage via `iptables` avec politique par défaut DROP.
* **Haute Disponibilité (HA) :** Cluster de pare-feux Actif/Passif avec **Keepalived (VRRP)**.
* **Accès Distant Sécurisé :** Tunnel **OpenVPN** pour l'administration.
* **Sécurité Web :** Serveur Nginx en **HTTPS** (TLS) avec redirection forcée.
* **Détection d'Intrusion :** Sonde **Snort** configurée pour détecter les scans et attaques.
* **Automatisation :** Script de validation automatique des tests de sécurité.

---

## ⚙️ Prérequis

* Machine virtuelle Ubuntu (20.04 ou 22.04 recommandé).
* Droits administrateur (`root` ou `sudo`).
* Python 3.

---

## 🚀 Installation et Démarrage

### Étape 1 : Préparation de l'environnement

Un script d'installation est fourni pour installer les dépendances (Mininet, OpenVPN, Snort, Nginx, etc.) et générer les certificats et configurations nécessaires.

1. Ouvrez un terminal dans le dossier du projet.
2. Rendez le script exécutable et lancez-le :
```bash
chmod +x setup_environment.sh
sudo ./setup_environment.sh
```

**Note :** Ce script génère automatiquement les clés SSL pour le serveur Web, les secrets OpenVPN et les fichiers de configuration dans `/home/server/`.

### Étape 2 : Lancement de l'Infrastructure

Le script Python orchestre la topologie Mininet, configure le routage, lance les services (VPN, IDS, Web) et active le pare-feu.
```bash
sudo python3 projet_topo.py
```

---

## ✅ Validation et Tests

Dès le lancement de la topologie, un module AutoValidator exécute automatiquement la checklist de validation (T1 à T12).

1. Observez le terminal : Les tests s'affichent en temps réel (VERT = PASS, ROUGE = FAIL).
2. Rapport de validation : À la fin de l'exécution, un fichier de rapport est généré à la racine :
   * `rapport_validation.json` (Contient les preuves techniques et outputs des commandes).

### Tests Manuels (CLI Mininet)

Une fois le script lancé et l'invite `mininet>` affichée, vous pouvez effectuer des tests manuels :

* **Ping (Connectivité) :**
```bash
mininet> attacker ping -c 1 10.0.0.20   # Succès (Intra-zone)
mininet> attacker ping -c 1 10.0.2.10   # Echec (Bloqué par FW)
```

* **Accès Web Sécurisé :**
```bash
mininet> attacker curl -k -I https://10.0.1.10
```

* **VPN (Connexion Admin) :**
```bash
mininet> admin openvpn --config /home/server/admin.ovpn --daemon
mininet> admin ping 10.8.0.1  # Ping dans le tunnel
```

* **Simulation de Panne (HA) :**
```bash
mininet> fw1 kill $(cat /run/keepalived_fw1.pid)
# Vérifier que FW2 prend le relais :
mininet> fw2 ip addr show
```

---

## 📂 Structure du Projet
```
.
├── projet_topo.py          # Script principal (Topologie + Tests Auto)
├── firewall.sh             # Script de configuration iptables (Zero Trust)
├── setup_environment.sh    # Script d'installation des dépendances
├── README.md               # Ce fichier
├── Rapport_Technique.pdf   # Rapport détaillé du projet
├── Configs/                # Fichiers de configuration de référence
│   ├── Keepalived/         # Confs Master/Backup
│   ├── OPENVPN/              # CONFIGURATION DE OPENVPN
    ├── Snort/              # Règles locales
    ├── SSH/              # CONFIGURATION DE SSH
│   └── Web/                # Config Nginx
└── Preuves/                # Screenshots et Logs de validation
```

---

## 🧹 Nettoyage

Pour arrêter proprement l'infrastructure et nettoyer les processus Mininet résiduels :

1. Dans le CLI Mininet, tapez `exit` ou faites `Ctrl+D`.
2. Si nécessaire, forcez le nettoyage :
```bash
sudo mn -c
```

---

© 2025 - Projet LSI3 
