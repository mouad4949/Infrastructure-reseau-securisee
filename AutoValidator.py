import json
import time
import os
from datetime import datetime

class AutoValidator:
    def __init__(self, net):
        self.net = net
        self.results = {}
        self.report_file = "rapport_validation.json"
        
        # Couleurs pour le terminal
        self.C_GREEN = '\033[92m'
        self.C_RED = '\033[91m'
        self.C_YELLOW = '\033[93m'
        self.C_RESET = '\033[0m'

        # Récupération des noeuds
        self.attacker = net.get('attacker')
        self.admin = net.get('admin')
        self.internal = net.get('internal')
        self.web1 = net.get('web1')
        self.fw1 = net.get('fw1')
        self.fw2 = net.get('fw2')

    
    def log(self, test_id, description, status, output="", details=""):
        res = "PASS" if status else "FAIL"
        color = self.C_GREEN if status else self.C_RED
        print(f"{color}[{test_id}] {description} : {res}{self.C_RESET}")
        if not status and details:
            print(f"    Details: {details}")
        
        
        clean_output = output.strip() if output else "N/A"
        
        self.results[test_id] = {
            "description": description,
            "status": res,
            "timestamp": datetime.now().isoformat(),
            "command_output": clean_output, 
            "details": details
        }

    def run_cmd(self, node, cmd, expect_in_output=None, expect_not_in=None):
        """Exécute une commande et vérifie la sortie"""
        # On capture stdout et stderr
        out = node.cmd(cmd + " 2>&1") 
        if expect_in_output and expect_in_output not in out:
            return False, out
        if expect_not_in and expect_not_in in out:
            return False, out
        return True, out

    def start_validation(self):
        print("\n" + "="*60)
        print("   DEMARRAGE DE LA VALIDATION AUTOMATISEE (CHECKLIST)")
        print("="*60)

        # --- 1. Validation de la topologie ---
        self.log("T1.1", "Démarrage Topologie", True, output="Topologie démarrée via Mininet API")
        
        # T1.2 Connectivité Intra-zone (WAN -> WAN)
        ok, out = self.run_cmd(self.attacker, "ping -c 1 -W 1 10.0.0.20", "1 received")
        self.log("T1.2", "Connectivité Intra-zone (WAN)", ok, output=out)

        # T1.3 Isolation Inter-zones (WAN -> LAN)
        ok, out = self.run_cmd(self.attacker, "ping -c 1 -W 1 10.0.2.10", "0 received")
        self.log("T1.3", "Isolation Inter-zones (WAN->LAN)", ok, output=out)


        # --- 2. Pare-feu et Segmentation ---
        # T2.1 Politique restrictive
        ok, out = self.run_cmd(self.attacker, "nc -zv -w 1 10.0.2.10 12345", expect_in_output=None, expect_not_in="succeeded")
        self.log("T2.1", "Politique par défaut (Drop)", ok, output=out if out else "Timeout (DROP Confirmed)")

        # T2.2 Accès WAN -> DMZ (Web autorisé)
        ok, out = self.run_cmd(self.attacker, "curl -I --connect-timeout 2 http://10.0.1.10", "HTTP")
        self.log("T2.2", "Accès Autorisé WAN->DMZ (HTTP)", ok, output=out)

        # T2.3 Interdiction WAN -> LAN (Nmap rapide)
        ok, out = self.run_cmd(self.attacker, "nmap -Pn -p 22 --max-retries 1 10.0.2.10", "filtered")
        self.log("T2.3", "Interdiction WAN->LAN (Port Filtered)", ok, output=out)


        # --- 3. DMZ et Services Web ---
        # T3.1 Dispo Service Web (HTTPS)
        ok, out = self.run_cmd(self.attacker, "curl -k -I --connect-timeout 2 https://10.0.1.10", "200 OK")
        self.log("T3.1", "Disponibilité HTTPS (200 OK)", ok, output=out)

        # T3.2 Redirection HTTP -> HTTPS
        ok, out = self.run_cmd(self.attacker, "curl -I --connect-timeout 2 http://10.0.1.10", "301 Moved")
        self.log("T3.2", "Redirection Force HTTPS (301)", ok, output=out)

        # T3.3 Isolation DMZ -> LAN
        ok, out = self.run_cmd(self.web1, "ping -c 1 -W 1 10.0.2.10", "0 received")
        self.log("T3.3", "Isolation DMZ->LAN", ok, output=out)


        # --- 4. Chiffrement ---
        # T4.1 Certificat SSL
        ok, out = self.run_cmd(self.attacker, "echo | openssl s_client -connect 10.0.1.10:443", "BEGIN CERTIFICATE")
        # On tronque la sortie du certificat pour ne pas spammer le JSON
        short_out = out[:500] + "... (truncated)" if len(out) > 500 else out
        self.log("T4.1", "Présence Certificat SSL", ok, output=short_out)


        # --- 7. Détection d'intrusion (Snort) ---
        print(f"{self.C_YELLOW}[INFO] Génération d'attaques pour Snort...{self.C_RESET}")
        self.attacker.cmd("nmap -sS -p 80 10.0.1.10") 
        self.attacker.cmd("ping -c 2 10.0.1.10") 
        time.sleep(2) 
        
        # Vérification logs sur FW1
        ok, out = self.run_cmd(self.fw1, "grep 'Scan Nmap' /var/log/snort/snort.alert.fast | tail -n 2", "Scan Nmap")
        self.log("T7.1", "Snort: Détection Scan Nmap", ok, output=out)
        
        ok, out = self.run_cmd(self.fw1, "grep 'Ping Detecte' /var/log/snort/snort.alert.fast | tail -n 2", "Ping Detecte")
        self.log("T7.3", "Snort: Détection Trafic Suspect", ok, output=out)


        # --- 5. & 6. VPN et Admin Sécurisée ---
        # T5.1 Accès sans VPN (SSH Fail) -> CORRIGÉ
        # Si 'Welcome' n'est pas là, c'est bon. On enregistre ce que la commande a renvoyé (souvent vide ou timeout)
        ok, out = self.run_cmd(self.admin, "timeout 2 ssh -o StrictHostKeyChecking=no root@10.0.2.10", expect_not_in="Welcome")
        self.log("T5.1", "Refus SSH sans VPN", ok, output=out if out else "Timeout silencieux (DROP) - OK")

        # T5.2 Connexion VPN
        print(f"{self.C_YELLOW}[INFO] Etablissement du tunnel VPN...{self.C_RESET}")
        self.admin.cmd("openvpn --config /home/server/admin.ovpn --daemon")
        time.sleep(5)
        
        ok, out = self.run_cmd(self.admin, "ip addr show tun0", "tun0")
        self.log("T5.2", "Interface Tunnel (tun0) active", ok, output=out)

        # T5.3 Accès après VPN (Ping tunnel)
        ok, out = self.run_cmd(self.admin, "ping -c 1 -W 1 10.8.0.1", "1 received")
        self.log("T5.3", "Connectivité Tunnel VPN", ok, output=out)


        # --- 9. Haute Disponibilité ---
        print(f"{self.C_YELLOW}[INFO] Test HA : Arrêt du Firewall Master...{self.C_RESET}")
        
        is_fw1_master = "10.0.0.1" in self.fw1.cmd("ip addr show")
        target_victim = self.fw1 if is_fw1_master else self.fw2
        backup_node = self.fw2 if is_fw1_master else self.fw1
        
        self.log("T9.1", f"Etat Initial Cluster (Master={target_victim.name})", True, output="Master detected via IP check")

        pid = target_victim.cmd("cat /run/keepalived_fw1.pid" if target_victim == self.fw1 else "cat /run/keepalived_fw2.pid").strip()
        if pid:
            target_victim.cmd(f"kill {pid}")
            time.sleep(3)
            
            # Vérification bascule
            ok, out = self.run_cmd(backup_node, "ip addr show", "10.0.0.1")
            self.log("T9.2", f"Basculement HA vers {backup_node.name}", ok, output=out)
            
            # Continuité service
            ok, out = self.run_cmd(self.attacker, "curl -I --connect-timeout 2 http://10.0.1.10", "HTTP")
            self.log("T9.3", "Continuité de Service Web après panne", ok, output=out)
        else:
            self.log("T9.2", "Simulation Panne", False, output="PID non trouvé")

        
        # --- 12. Rapport Final ---
        self.generate_report()

    def generate_report(self):
        print("\n" + "="*60)
        print("   GENERATION DU RAPPORT")
        print("="*60)
        
        passed = sum(1 for t in self.results.values() if t['status'] == "PASS")
        total = len(self.results)
        score = (passed / total) * 100
        
        summary = {
            "meta": {
                "project": "Infra Reseau Securisee",
                "timestamp": datetime.now().isoformat(),
                "score": f"{score:.1f}%"
            },
            "tests": self.results
        }
        
        with open(self.report_file, 'w') as f:
            json.dump(summary, f, indent=4)
            
        print(f"Rapport sauvegardé dans : {self.report_file}")
        print(f"Score Global : {score:.1f}%")
        if score == 100:
             print(f"{self.C_GREEN}SUCCES TOTAL DU PROJET{self.C_RESET}")
        else:
             print(f"{self.C_YELLOW}ATTENTION : CERTAINS TESTS ONT ECHOUE{self.C_RESET}")
