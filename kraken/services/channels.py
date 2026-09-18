import subprocess
import threading


class ChannelHopper:
    def __init__(
        self, iface: str, delay: float, channels: range = range(1, 14)
    ) -> None:
        self.iface = iface
        self.delay = delay
        self.channels = channels
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> threading.Event:
        if self.thread and self.thread.is_alive():
            return self.stop_event

        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._hop, name="kraken-channel-hopper", daemon=True
        )
        self.thread.start()

        return self.stop_event

    def stop(self) -> None:
        self.stop_event.set()

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=max(self.delay * 2, 0.5))

    def _hop(self) -> None:
        while not self.stop_event.is_set():
            for channel in self.channels:
                if self.stop_event.is_set():
                    return

                subprocess.run(
                    ["iw", self.iface, "set", "channel", str(channel)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

                self.stop_event.wait(self.delay)
