

'''

Le programme est décomposée en plusieurs actions de la reocnnaissance passive 
sniff = sniffer une interface
icmp = envoyer un ICMP custom
syn = envoyer un TCP SYN

spoof (envoyer un paquet avec IP source falsifiée)
pcap  (sauvegarder la capture)

Chaque action correspond à une fonction  
'''


# parse arguments

def sniff_interface(interface, count, filter):
    sniff(iface=interface, count=count, filter=filter)
