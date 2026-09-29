from scapy.all import sniff, wrpcap

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


# parse arguments

def sniff_interface(interface, count, filter):
    sniff(iface=interface, count=count, filter=filter)
