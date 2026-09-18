from scapy.layers.dot11 import Dot11Elt
from scapy.packet import Packet


def get_encryption(pkt: Packet) -> str:
    if not pkt.haslayer(Dot11Elt):
        return "Open"

    elt = pkt.getlayer(Dot11Elt)

    while elt is not None:
        if elt.ID == 48 and b"\x00\x0f\xac\x04" in elt.info:
            return "WPA2"

        if elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):
            return "WPA"

        elt = elt.payload.getlayer(Dot11Elt)

    return "WEP"
