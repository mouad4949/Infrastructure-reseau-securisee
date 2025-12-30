#!/usr/bin/python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os
from AutoValidator import AutoValidator

class InfrastructureTopo(Topo):
    def build(self):
        # Zones (Switchs)
        s_wan = self.addSwitch('s1')
        s_dmz = self.addSwitch('s2')
        s_lan = self.addSwitch('s3')

        # Hotes
        attacker = self.addHost('attacker', ip='10.0.0.10/24')
        admin = self.addHost('admin', ip='10.0.0.20/24')
        web1 = self.addHost('web1', ip='10.0.1.10/24')
        internal = self.addHost('internal', ip='10.0.2.10/24')

        # Cluster HA (Firewalls)
        fw1 = self.addHost('fw1', ip='10.0.0.2/24')
        fw2 = self.addHost('fw2', ip='10.0.0.3/24')

        # Liens Firewalls (WAN=eth0, DMZ=eth1, LAN=eth2)
        for f in [fw1, fw2]:
            self.addLink(f, s_wan)
            self.addLink(f, s_dmz)
            self.addLink(f, s_lan)

        # Liens Hotes
        self.addLink(attacker, s_wan)
        self.addLink(admin, s_wan)
        self.addLink(web1, s_dmz)
        self.addLink(internal, s_lan)

def run_internal_tests(net):
    print("\n" + "="*50)
    print("   RAPPORT DE VALIDATION INTERNE")
    print("="*50)
    attacker = net.get('attacker')
    
    # Test 1 : Gateway VIP (avec timeout de 2s)
    res1 = attacker.cmd("timeout 2 ping -c 1 -W 1 10.0.0.1")
    print(f"Firewall VIP (10.0.0.1) : {'OK' if '1 received' in res1 else 'FAIL'}")
    
    # Test 2 : HTTPS DMZ (avec timeout de 2s)
    res2 = attacker.cmd("curl -k -I --connect-timeout 2 https://10.0.1.10")
    print(f"Service DMZ (HTTPS)     : {'OK' if '200' in res2 else 'FAIL'}")
    
    # Test 3 : Redirection HTTP
    res3 = attacker.cmd("curl -I --connect-timeout 2 http://10.0.1.10")
    print(f"Redirection HTTP        : {'OK' if '301' in res3 else 'FAIL'}")
    
    # Test 4 : Zero Trust
    res4 = attacker.cmd("timeout 2 ping -c 1 -W 1 10.0.2.10")
    print(f"Isolation LAN           : {'OK' if '0 received' in res4 else 'FAIL'}")
    print("="*50 + "\n")

def run():
    # 0. Nettoyage preventif
    print("*** Nettoyage des processus residuels ***")
    os.system("mn -c > /dev/null 2>&1")
    os.system('pkill -9 -f "keepalived|snort|nginx"')
    os.system('rm -f /run/keepalived*.pid /run/vrrp*.pid')

    topo = InfrastructureTopo()
    net = Mininet(topo=topo, controller=OVSController)
    net.start()
    
    fw1, fw2 = net.get('fw1', 'fw2')
    web1, internal = net.get('web1', 'internal')
    attacker, admin = net.get('attacker', 'admin')

    print("*** Configuration des IPs fixes et du Firewall ***")
    for f, suffix in [(fw1, '2'), (fw2, '3')]:
        f.cmd(f'ifconfig {f.name}-eth1 10.0.1.{suffix} netmask 255.255.255.0')
        f.cmd(f'ifconfig {f.name}-eth2 10.0.2.{suffix} netmask 255.255.255.0')
        f.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
        f.cmd('chmod +x /home/server/firewall.sh')
        f.cmd('/home/server/firewall.sh')

    print("*** Lancement de Keepalived (HA Cluster) ***")
    # Utilisation de fichiers PID distincts pour eviter les conflits
    fw1.cmd('keepalived -f /home/server/keepalived_fw1.conf -p /run/keepalived_fw1.pid -r /run/vrrp_fw1.pid')
    fw2.cmd('keepalived -f /home/server/keepalived_fw2.conf -p /run/keepalived_fw2.pid -r /run/vrrp_fw2.pid')
    
    print("*** Attente de l election du Master (5s) ***")
    time.sleep(5) 

    print("*** Configuration des routes par defaut ***")
    attacker.cmd('ip route add default via 10.0.0.1')
    admin.cmd('ip route add default via 10.0.0.1')
    web1.cmd('ip route add default via 10.0.1.1')
    internal.cmd('ip route add default via 10.0.2.1')

    print("*** Lancement des services (Nginx, SSH, Snort) ***")
    os.system('service nginx stop')
    # On lance Nginx en redirigeant tout pour ne pas bloquer le shell
    web1.cmd('nginx > /dev/null 2>&1 &')
    # On lance SSH
    web1.cmd('/usr/sbin/sshd -f /home/server/sshd_config_secure > /dev/null 2>&1 &')
    # On lance Snort en mode SILENCIEUX (sans console)
    fw1.cmd('snort -q -c /etc/snort/snort.conf -i fw1-eth0 -D')
    print("   Lancement OpenVPN sur FW1 et FW2...")
    # On lance OpenVPN en arrière-plan sur les deux FW
    fw1.cmd('openvpn --config /home/server/openvpn_server.conf --daemon')
    fw2.cmd('openvpn --config /home/server/openvpn_server.conf --daemon')
    # Generation du rapport avant d'ouvrir le CLI
    validator = AutoValidator(net)
    validator.start_validation()

    print("*** INFRASTRUCTURE OPERATIONNELLE ***")
    CLI(net)
    
    # Nettoyage a la fermeture
    print("*** Fermeture et nettoyage ***")
    os.system('pkill -9 -f "keepalived|snort|nginx"')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
