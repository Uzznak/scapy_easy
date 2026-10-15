# Scapy Easy

Outil de base de reconnaissance active basé sur Scapy, créé dans le cadre du module Netacad 3.2 – Effectuer une reconnaissance active.
Il permet d’apprendre à manipuler des paquets réseau et à réaliser des actions de base utilisées en pentest.

## Fonctionnalités
- Sniffing réseau  
Capture de paquets sur une interface, filtrage, export en .pcap.

- ICMP personnalisé  
Création et envoi d’un paquet ICMP avec payload custom.

- Scan TCP SYN  
Envoi d’un SYN et analyse de la réponse (SA = ouvert, RA = fermé).

- Spoofing simple  
Envoi d’un ICMP avec adresse source falsifiée.

## Utilisation

sudo python3 recon.py --sniff --interface eth0 --filter icmp --count 10  
sudo python3 recon.py --icmp 10.0.0.5 --payload "Hello"  
sudo python3 recon.py --syn 10.0.0.5 --port 80  
sudo python3 recon.py --spoof 10.0.0.5 --fake-src 192.168.1.100  
