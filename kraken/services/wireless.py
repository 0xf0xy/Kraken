import subprocess
from dataclasses import dataclass


class WirelessError(RuntimeError):
    pass


@dataclass(slots=True)
class WirelessManager:
    phy: str = "phy0"
    monitor_interface: str = "mon0"
    managed_interface: str = "wlan0"

    def start_monitor(self, iface: str) -> str:
        self._run(["systemctl", "stop", "NetworkManager"], check=False)
        self._run(["systemctl", "stop", "wpa_supplicant"], check=False)
        self._run(["iw", "dev", iface, "del"])
        self._run(
            [
                "iw",
                "phy",
                self.phy,
                "interface",
                "add",
                self.monitor_interface,
                "type",
                "monitor",
            ]
        )
        self._run(["ip", "link", "set", self.monitor_interface, "up"])

        return self.monitor_interface

    def stop_monitor(self, iface: str) -> str:
        self._run(["iw", "dev", iface, "del"])
        self._run(
            [
                "iw",
                "phy",
                self.phy,
                "interface",
                "add",
                self.managed_interface,
                "type",
                "managed",
            ]
        )
        self._run(["ip", "link", "set", self.managed_interface, "up"])
        self._run(["systemctl", "start", "wpa_supplicant"], check=False)
        self._run(["systemctl", "start", "NetworkManager"], check=False)

        return self.managed_interface

    def set_channel(self, iface: str, channel: int) -> None:
        self._run(["iw", iface, "set", "channel", str(channel)])

    @staticmethod
    def _run(
        command: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(command, check=check, text=True)

        except (OSError, subprocess.CalledProcessError) as exc:
            raise WirelessError(
                f"Wireless command failed: {' '.join(command)}"
            ) from exc
