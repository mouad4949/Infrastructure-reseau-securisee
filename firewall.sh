#!/bin/bash

# 1. ACTIVATION DU ROUTAGE ET DESACTIVATION DU RP_FILTER (CRUCIAL)
echo 1 > /proc/sys/net/ipv4/ip_forward
# On désactive la vérification stricte du chemin (sinon Linux jette les paquets VIP)
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $i; done

# 2. NETTOYAGE
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 1. OPENVPN - Autoriser la connexion UDP 1194 depuis l'Admin (WAN)
# On autorise l'admin (10.0.0.20) à se connecter au VPN
iptables -A INPUT -p udp --dport 1194 -s 10.0.0.20 -j ACCEPT

# 2. TUNNEL - Autoriser le trafic venant du VPN (tun+) vers le LAN et la DMZ
# Les clients VPN (10.8.0.x) peuvent accéder à tout
iptables -A FORWARD -i tun+ -o fw+-eth1 -j ACCEPT  # Vers DMZ
iptables -A FORWARD -i tun+ -o fw+-eth2 -j ACCEPT  # Vers LAN

# 3. TUNNEL - Autoriser le retour
iptables -A FORWARD -i fw+-eth1 -o tun+ -j ACCEPT
iptables -A FORWARD -i fw+-eth2 -o tun+ -j ACCEPT

# 3. REGLES DE BASE (Loopback, HA, Ping)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p vrrp -j ACCEPT
iptables -A INPUT -d 224.0.0.18 -j ACCEPT
# Autoriser le PING partout pour le diagnostic
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT

# 4. MAINTIEN DES CONNEXIONS (Le retour des paquets)
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# 5. REGLES DE ZONES (Simplifiées pour être sûr que ça marche)
# On utilise "-i fw+" qui couvre fw1-eth0, fw1-eth1, fw2-eth0, etc.

# WAN -> DMZ (Web)
iptables -A FORWARD -i fw+ -d 10.0.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i fw+ -d 10.0.1.10 -p tcp --dport 443 -j ACCEPT

# ADMIN -> DMZ (SSH)
iptables -A FORWARD -i fw+ -s 10.0.0.20 -d 10.0.1.10 -p tcp --dport 22 -j ACCEPT

# LAN -> DMZ
iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -j ACCEPT

# LOGS (Pour voir si ça bloque encore)
iptables -A FORWARD -j LOG --log-prefix "FW_DROP: "
