from collections.abc import Callable

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Packet

from kraken.services.encryption import get_encryption
from kraken.core.models import Network


class NetworkScanner:
    def __init__(self) -> None:
        self.networks: dict[str, Network] = {}

    def process_packet(self, pkt: Packet) -> Network | None:
        if not pkt.haslayer(Dot11Beacon):
            return None

        bssid = (pkt[Dot11].addr2 or "").upper()

        if not bssid:
            return None

        ssid = self._get_ssid(pkt)
        signal = self._get_signal(pkt)
        channel = self._get_channel(pkt)

        encryption = get_encryption(pkt)

        network = self.networks.get(bssid)
        if network is None:
            network = Network(
                ssid=ssid,
                bssid=bssid,
                signal=signal,
                channel=channel if channel is not None else "-",
                encryption=encryption,
            )
            self.networks[bssid] = network

        else:
            network.signal = signal
            network.ssid = ssid or network.ssid
            network.encryption = encryption

            if channel is not None:
                network.channel = channel

            network.beacons += 1

        return network

    @staticmethod
    def _get_ssid(pkt: Packet) -> str:
        elt = pkt.getlayer(Dot11Elt)

        if elt is None:
            return ""

        try:
            value = elt.info.decode("utf-8", errors="ignore")

        except (AttributeError, UnicodeDecodeError):
            return ""

        return value

    @staticmethod
    def _get_signal(pkt: Packet) -> int | str:
        try:
            return pkt.dBm_AntSignal

        except AttributeError:
            return "N/A"

    @staticmethod
    def _get_channel(pkt: Packet) -> int | None:
        elt = pkt.getlayer(Dot11Elt)

        while elt:
            if elt.ID == 3 and elt.info:
                return elt.info[0]

            elt = elt.payload.getlayer(Dot11Elt)

        return None

    def scan(
        self,
        iface: str,
        packet_callback: Callable[[dict[str, Network]], None] | None = None,
    ) -> dict[str, Network]:
        from scapy.all import sniff

        def handler(pkt: Packet) -> None:
            network = self.process_packet(pkt)

            if network is not None and packet_callback is not None:
                packet_callback(self.networks)

        sniff(iface=iface, prn=handler)

        return self.networks
