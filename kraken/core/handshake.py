from collections.abc import Callable

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, EAPOL, Packet, sniff


class HandshakeCapture:
    def __init__(self, target_bssid: str) -> None:
        self.target_bssid = target_bssid.upper()
        self.ssid: str | None = None
        self.client: str | None = None
        self.anonce: str | None = None
        self.snonce: str | None = None
        self.mic: str | None = None
        self.eapol: str | None = None
        self.clients: set[str] = set()

    @property
    def complete(self) -> bool:
        return all((self.anonce, self.snonce, self.mic, self.eapol))

    def process_packet(self, pkt: Packet) -> bool:
        updated = False

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            updated |= self._process_beacon(pkt)

        elif pkt.haslayer(EAPOL):
            updated |= self._process_eapol(pkt)

        elif pkt.haslayer(Dot11) and pkt.type == 2:
            updated |= self._process_data(pkt)

        return updated

    def _process_beacon(self, pkt: Packet) -> bool:
        source = (pkt.addr2 or "").upper()

        if self.ssid is not None or source != self.target_bssid:
            return False

        elt = pkt.getlayer(Dot11Elt)

        ssid = ""
        while elt is not None:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="ignore")

                except (AttributeError, UnicodeDecodeError):
                    ssid = ""

                break

            elt = elt.payload.getlayer(Dot11Elt)

        self.ssid = ssid if ssid else "<hidden>"

        return True

    def _process_eapol(self, pkt: Packet) -> bool:
        src = (pkt.addr2 or "").upper()
        dst = (pkt.addr1 or "").upper()

        if self.target_bssid not in (src, dst):
            return False

        try:
            raw = bytes(pkt.getlayer(EAPOL))

        except (TypeError, ValueError):
            return False

        if len(raw) < 7:
            return False

        key_info = int.from_bytes(raw[5:7], "big")
        key_ack = bool(key_info & 0x0080)
        key_mic = bool(key_info & 0x0100)

        if src == self.target_bssid and key_ack and not key_mic:
            self.client = dst or None
            self.anonce = self._extract_anonce(raw)
            return True

        if (
            dst == self.target_bssid
            and src == self.client
            and not key_ack
            and key_mic
            and self.anonce
            and not self.snonce
        ):
            self.snonce = self._extract_snonce(raw)
            self.mic = self._extract_mic(raw)
            self.eapol = raw.hex()
            return True

        return False

    def _process_data(self, pkt: Packet) -> bool:
        src = (pkt.addr2 or "").upper()
        dst = (pkt.addr1 or "").upper()
        bssid = (pkt.addr3 or "").upper()
        broadcast = "FF:FF:FF:FF:FF:FF"

        client = None

        if self.target_bssid == src and dst != broadcast:
            client = dst

        elif self.target_bssid == dst and src != broadcast:
            client = src

        elif self.target_bssid == bssid:
            if src != self.target_bssid and src != broadcast:
                client = src

            elif dst != self.target_bssid and dst != broadcast:
                client = dst

        if client and len(self.clients) < 5:
            before = len(self.clients)
            self.clients.add(client)
            return len(self.clients) != before

        return False

    @staticmethod
    def _extract_anonce(raw: bytes) -> str:
        return raw.hex()[34:98]

    @staticmethod
    def _extract_snonce(raw: bytes) -> str:
        return raw.hex()[34:98]

    @staticmethod
    def _extract_mic(raw: bytes) -> str:
        return raw.hex()[162:194]

    def to_dict(self) -> dict[str, str | None]:
        return {
            "ssid": self.ssid,
            "bssid": self.target_bssid,
            "client": self.client,
            "anonce": self.anonce,
            "snonce": self.snonce,
            "mic": self.mic,
            "eapol": self.eapol,
        }

    def capture(
        self,
        iface: str,
        packet_callback: Callable[["HandshakeCapture"], None] | None = None,
    ) -> "HandshakeCapture":
        def handler(pkt: Packet) -> None:
            updated = self.process_packet(pkt)

            if updated and packet_callback is not None:
                packet_callback(self)

        sniff(iface=iface, prn=handler, stop_filter=lambda _: self.complete)

        return self
