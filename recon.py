#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# On importe les fonctions principales de Scapy
from scapy.all import sniff, wrpcap, IP, ICMP, TCP, send, sr1

# On importe argparse pour gérer les arguments en ligne de commande
import argparse
import os

 """
    Capture du trafic réseau sur une interface donnée.

    interface : nom de l'interface (ex: 'eth0', 'br-internal')
    count     : nombre de paquets à capturer (0 = illimité jusqu'à CTRL-C)
    flt       : filtre BPF (ex: 'icmp', 'tcp', 'port 80')
    savefile  : nom du fichier .pcap pour sauvegarder la capture
    """

    print(f"Sniffing de l'{interface} ...")
    if flt:
        print(f"Filtre appliqué : {flt}")

# Capture des paquets
    packets = sniff(iface=interface, count=count, filter=flt)

    print(f"Capture terminée : {len(packets)} paquets collectés")

# Affichage résumé
    print("Résumé des paquets :")
    packets.summary()

    # Sauvegarde si demandée
    if savefile:
        wrpcap(savefile, packets)
        print(f"Capture sauvegardée dans {savefile}")

    return packets


packets


def send_icmp(dst, payload="Test ICMP"):
    # Fonction pour envoyer un paquet ICMP simple vers une cible

    print(f"[+] Envoi d'un paquet ICMP vers {dst}")
    print(f"[+] Charge utile : {payload}")

    # On construit le paquet :
    # IP(dst=dst) = couche IP avec adresse de destination
    # ICMP() = couche ICMP par défaut (type echo request)
    # /payload = ajout de données (texte) dans le paquet
    pkt = IP(dst=dst) / ICMP() / payload

    # On affiche le détail du paquet pour comprendre sa structure
    print("[+] Détail du paquet ICMP :")
    pkt.show()

    # On envoie le paquet sur le réseau
    send(pkt)

    print("[+] Paquet ICMP envoyé.")


def syn_scan(dst, port):
    # Fonction pour envoyer un paquet TCP SYN vers un port donné

    print(f"[+] Scan SYN vers {dst}:{port}")

    # On construit le paquet :
    # IP(dst=dst) = couche IP avec adresse de destination
    # TCP(dport=port, flags="S") = couche TCP avec port destination et flag SYN
    pkt = IP(dst=dst) / TCP(dport=port, flags="S")

    # On affiche le paquet pour voir sa structure
    print("[+] Détail du paquet SYN :")
    pkt.show()

    # sr1() envoie le paquet et attend UNE réponse
    # La réponse peut être None si rien ne revient
    resp = sr1(pkt, timeout=2, verbose=0)

    # On analyse la réponse
    if resp is None:
        # Aucun paquet reçu
        print("[!] Aucun retour, le port est peut-être filtré ou la cible ne répond pas.")
    else:
        # On affiche la réponse reçue
        print("[+] Réponse reçue :")
        resp.show()

        # On regarde les flags TCP de la réponse
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            # Si les flags sont SA (SYN + ACK), le port est ouvert
            if flags == 0x12:  # 0x12 = SYN+ACK
                print("[+] Port ouvert (SYN+ACK reçu).")
            # Si les flags sont RA (RST + ACK), le port est fermé
            elif flags == 0x14:  # 0x14 = RST+ACK
                print("[+] Port fermé (RST+ACK reçu).")
            else:
                print(f"[?] Flags TCP inattendus : {flags}")
        else:
            print("[?] Pas de couche TCP dans la réponse.")


def spoof_icmp(dst, fake_src, payload="Spoofed ICMP"):
    # Fonction pour envoyer un ICMP avec une adresse source falsifiée

    print(f"[+] Envoi d'un ICMP usurpé vers {dst}")
    print(f"[+] Adresse source falsifiée : {fake_src}")
    print(f"[+] Charge utile : {payload}")

    # On construit le paquet :
    # IP(src=fake_src, dst=dst) = on force l'adresse source
    pkt = IP(src=fake_src, dst=dst) / ICMP() / payload

    # On affiche le paquet pour voir la source falsifiée
    print("[+] Détail du paquet ICMP usurpé :")
    pkt.show()

    # On envoie le paquet
    send(pkt)

    print("[+] Paquet ICMP usurpé envoyé.")


def main():
    # Fonction principale qui gère les arguments et appelle les bonnes fonctions

    # On crée un parseur d'arguments
    parser = argparse.ArgumentParser(
        description="Petit outil de reconnaissance active avec Scapy (sniff, ICMP, SYN, spoof)."
    )

    # Option pour sniffer
    parser.add_argument(
        "--sniff",
        action="store_true",
        help="Activer le mode sniffing sur une interface."
    )

    # Interface réseau pour le sniff
    parser.add_argument(
        "--interface",
        type=str,
        default="eth0",
        help="Interface réseau à utiliser (par défaut : eth0)."
    )

    # Nombre de paquets à capturer
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Nombre de paquets à capturer (0 = illimité jusqu'à CTRL-C)."
    )

    # Filtre BPF pour le sniff
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Filtre BPF (ex: 'icmp', 'tcp', 'port 80')."
    )

    # Fichier de sortie pour la capture
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Nom du fichier .pcap pour sauvegarder la capture."
    )

    # Option pour envoyer un ICMP
    parser.add_argument(
        "--icmp",
        type=str,
        help="Adresse IP de destination pour envoyer un paquet ICMP."
    )

    # Charge utile ICMP
    parser.add_argument(
        "--payload",
        type=str,
        default="Test ICMP",
        help="Texte à inclure dans le paquet ICMP."
    )

    # Option pour envoyer un SYN
    parser.add_argument(
        "--syn",
        type=str,
        help="Adresse IP de destination pour un scan SYN."
    )

    # Port pour le SYN
    parser.add_argument(
        "--port",
        type=int,
        default=80,
        help="Port TCP à scanner avec un SYN (par défaut : 80)."
    )

    # Option pour spoofing ICMP
    parser.add_argument(
        "--spoof",
        type=str,
        help="Adresse IP de destination pour un ICMP usurpé."
    )

    # Adresse source falsifiée
    parser.add_argument(
        "--fake-src",
        type=str,
        default="1.2.3.4",
        help="Adresse IP source falsifiée pour le spoofing ICMP."
    )

    # On récupère les arguments
    args = parser.parse_args()

    # On vérifie si le script est lancé en root (important pour Scapy)
    if os.geteuid() != 0:
        print("[!] Ce script doit être exécuté en root (sudo) pour fonctionner correctement.")
        return

    # Si l'utilisateur a demandé le sniff
    if args.sniff:
        sniff_interface(
            interface=args.interface,
            count=args.count,
            flt=args.filter,
            savefile=args.pcap
        )

    # Si l'utilisateur a demandé un ICMP
    if args.icmp:
        send_icmp(dst=args.icmp, payload=args.payload)

    # Si l'utilisateur a demandé un SYN
    if args.syn:
        syn_scan(dst=args.syn, port=args.port)

    # Si l'utilisateur a demandé un spoof ICMP
    if args.spoof:
        spoof_icmp(dst=args.spoof, fake_src=args.fake_src, payload=args.payload)

    # Si aucune option n'a été utilisée, on affiche un message
    if not (args.sniff or args.icmp or args.syn or args.spoof):
        print("[!] Aucune action spécifiée.")
        print("    Exemple :")
        print("    sudo python3 recon.py --sniff --interface br-internal --filter icmp --count 10")
        print("    sudo python3 recon.py --icmp 10.6.6.23 --payload \"Ceci est un test\"")
        print("    sudo python3 recon.py --syn 10.6.6.23 --port 445")
        print("    sudo python3 recon.py --spoof 10.6.6.23 --fake-src 192.168.1.100")


# Point d'entrée du script : on appelle main() si le fichier est exécuté directement
if __name__ == "__main__":
    main()






