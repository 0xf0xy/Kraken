from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Network:
    ssid: str
    bssid: str
    signal: int | str
    channel: int | str
    encryption: str
    beacons: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "signal": self.signal,
            "channel": self.channel,
            "encryption": self.encryption,
            "beacons": self.beacons,
        }


@dataclass(slots=True)
class Handshake:
    ssid: str | None = None
    bssid: str | None = None
    client: str | None = None
    anonce: str | None = None
    snonce: str | None = None
    mic: str | None = None
    eapol: str | None = None

    @property
    def complete(self) -> bool:
        return all((self.anonce, self.snonce, self.mic, self.eapol))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "client": self.client,
            "anonce": self.anonce,
            "snonce": self.snonce,
            "mic": self.mic,
            "eapol": self.eapol,
        }
