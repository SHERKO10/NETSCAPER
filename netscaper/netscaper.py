import scapy.all as scapy
import psutil
from datetime import datetime
import os
import csv
import sys
import ctypes




packets = []
packets_pcap = []






def capture_reseau(packet):

    pkt_dict = {}
    temps = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
    pkt_dict['Time'] = temps

    if packet.haslayer(scapy.IP):
        pkt_dict['Type'] = 'IP'
        pkt_dict['Source'] = packet[scapy.IP].src
        pkt_dict['Destination'] = packet[scapy.IP].dst
        pkt_dict['Protocol'] = packet[scapy.IP].proto
        
       
        


        if packet.haslayer(scapy.TCP):
            pkt_dict['Source Port'] = packet[scapy.TCP].sport
            pkt_dict['Destination Port'] = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            pkt_dict['Source Port'] = packet[scapy.UDP].sport
            pkt_dict['Destination Port'] = packet[scapy.UDP].dport
    
    elif packet.haslayer(scapy.ARP):
        pkt_dict['Type'] = 'ARP'
        pkt_dict['Source'] = packet[scapy.ARP].psrc
        pkt_dict['Destination'] = packet[scapy.ARP].pdst
        pkt_dict['Protocol'] = 'ARP'
        pkt_dict['Source Port'] = pkt_dict['Destination Port'] = None
      
    
    else:
        return  # Ignorer les autres types de paquets


    pkt_dict['Taille_packet'] = len(packet)


    print(f"{pkt_dict['Time']} | {pkt_dict['Type']} | {pkt_dict['Source']}:{pkt_dict.get('Source Port', '')} -> {pkt_dict['Destination']}:{pkt_dict.get('Destination Port', '')} | Protocol: {pkt_dict['Protocol']} | Taille: {pkt_dict['Taille_packet']} bytes")

    print(packet.summary())
    packets.append(pkt_dict)
    packets_pcap.append(packet)
            


def check_root():
    """Vérifie si le script est exécuté avec les privilèges root."""

    if os.name == 'nt':
        # Windows
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Ce script doit être exécuté en tant qu'administrateur.")
            sys.exit(1)
    else:
        # Unix/Linux
        if os.geteuid() != 0:
            print("Ce script doit être exécuté en tant que root.")
            sys.exit(1)
    


def main():
    print(r"""



 ____    __  __  ____    ____    __  __   _____         ____                   
/\  _`\ /\ \/\ \/\  _`\ /\  _`\ /\ \/\ \ /\  __`\     /|  _ \                  
\ \,\L\_\ \ \_\ \ \ \L\_\ \ \L\ \ \ \/'/'\ \ \/\ \    |/\   |                  
 \/_\__ \\ \  _  \ \  _\L\ \ ,  /\ \ , <  \ \ \ \ \    \// __`\/\              
   /\ \L\ \ \ \ \ \ \ \L\ \ \ \\ \\ \ \\`\ \ \ \_\ \   /|  \L>  <_             
   \ `\____\ \_\ \_\ \____/\ \_\ \_\ \_\ \_\\ \_____\  | \_____/\/             
    \/_____/\/_/\/_/\/___/  \/_/\/ /\/_/\/_/ \/_____/   \/____/\/              
                                                                               
                                                                               
                       __      __  ______   __  __  __  __  ____    ____       
                      /\ \  __/\ \/\__  _\ /\ \/\ \/\ \/\ \/\  _`\ /\  _`\     
                      \ \ \/\ \ \ \/_/\ \/ \ \ `\\ \ \ `\\ \ \ \L\_\ \ \L\ \   
                       \ \ \ \ \ \ \ \ \ \  \ \ , ` \ \ , ` \ \  _\L\ \ ,  /   
                        \ \ \_/ \_\ \ \_\ \__\ \ \`\ \ \ \`\ \ \ \L\ \ \ \\ \  
                         \ `\___x___/ /\_____\\ \_\ \_\ \_\ \_\ \____/\ \_\ \_\
                          '\/__//__/  \/_____/ \/_/\/_/\/_/\/_/\/___/  \/_/\/ /


    NETSCAPER - Mini Wireshark v1.0
    Auteur: SHERKO & Winner""")


    check_root()
    p = None
    try:
        iface = choisir_interface()
        if iface:
            print(f"Prêt à sniffer sur l'interface : {iface}\n")
            print("Appuyez sur Ctrl+C pour arrêter.\n")
            p = scapy.sniff(iface=iface, prn=capture_reseau)
            print(p)

    except KeyboardInterrupt:
        print("\nArrêt du sniffer.")
    




    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    enregistrer_csv(packets, f"packets_{timestamp}.csv")
    enregistrer_pcap(packets_pcap, f"packets_{timestamp}.pcap")
        

def choisir_interface():
    """Liste les interfaces réseau et permet à l'utilisateur d'en choisir une."""
    interfaces = list(psutil.net_if_addrs().keys())
    if not interfaces:
        print("Aucune interface réseau disponible.")
        return None
    

    print("\nInterfaces réseau disponibles :\n")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    
    while True:
        choix = input("Choissisez une interface sur laquelle sniffer : ")
        if choix.isdigit():
            choix = int(choix)
            if 0 <= choix < len(interfaces):
                print(f"Interface choisie : {interfaces[choix]}\n")
                return interfaces[choix]
        print("Choix invalide. Veuillez réessayer.")


def enregistrer_csv(packets, nom_fichier='packets.csv'):
    """Enregistre les paquets capturés dans un fichier CSV."""
    
    if not packets:
        print("Aucun paquet à enregistrer.")
        return

    colonnes = packets[0].keys()

    with open(nom_fichier, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=colonnes)
        writer.writeheader()
        writer.writerows(packets)

        print(f"Trafic enregistré dans {nom_fichier}")


def enregistrer_pcap(packets, nom_fichier='packets.pcap'):
    """Enregistre les paquets capturés dans un fichier PCAP. Pour la compatibilité avec Wireshark."""
    if not packets:
        print("Aucun paquet à enregistrer.")
        return

    scapy.wrpcap(nom_fichier, packets)
    print(f"Trafic enregistré dans {nom_fichier}")




if __name__ == '__main__':
    main()