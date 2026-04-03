"""
MIT License

Copyright (c) 2026 0xf0xy

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

from scapy.all import Packet, Dot11Elt
import subprocess
import threading
import hashlib
import time
import hmac
import os

RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
RESET = "\033[0m"


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


def check_password(
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
    B = min(ap, client) + max(ap, client) + min(anonce, snonce) + max(anonce, snonce)
    ptk = PRF512(pmk, A, B)
    mic_key = ptk[:16]
    eapol_zeroed = bytearray(eapol)
    eapol_zeroed[81:97] = b"\x00" * 16
    new_mic = hmac.new(mic_key, eapol_zeroed, hashlib.sha1).digest()[:16]

    if new_mic == mic:
        return password

    return False


def start_monitor(iface: str):
    """
    Start monitor mode on the specified interface.

    Args:
        iface (str): Network interface to set to monitor mode.
    """
    os.system("clear")

    print(f"Enabling monitor mode on interface {BLUE}{iface}{RESET}")
    print("─" * 55)

    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=False)
        subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=False)
        subprocess.run(["iw", "dev", iface, "del"], check=True)
        subprocess.run(
            ["iw", "phy", "phy0", "interface", "add", "mon0", "type", "monitor"],
            check=True,
        )
        subprocess.run(["ip", "link", "set", "mon0", "up"], check=True)

        print(
            f"    [{GREEN}✓{RESET}] Interface 'mon0' created in {GREEN}monitor{RESET} mode.\n"
        )

    except subprocess.CalledProcessError:
        print(f"    [{RED}x{RESET}] Failed to change interface '{iface}' mode.\n")


def stop_monitor(iface: str):
    """
    Stop monitor mode on the specified interface.

    Args:
        iface (str): Network interface to stop monitor mode on.
    """
    os.system("clear")

    print(f"Disabling monitor mode on interface {BLUE}{iface}{RESET}")
    print("─" * 55)

    try:
        subprocess.run(["iw", "dev", iface, "del"], check=True)
        subprocess.run(
            ["iw", "phy", "phy0", "interface", "add", "wlan0", "type", "managed"],
            check=True,
        )
        subprocess.run(["ip", "link", "set", "wlan0", "up"], check=True)
        subprocess.run(["systemctl", "start", "wpa_supplicant"], check=False)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=False)

        print(
            f"    [{GREEN}✓{RESET}] Interface '{iface}' is now in {GREEN}managed{RESET} mode.\n"
        )

    except subprocess.CalledProcessError:
        print(f"    [{RED}x{RESET}] Failed to change interface '{iface}' mode.\n")


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


def display_dump(
    mode: str, data: dict, bssid: str = None, channel: int = None, clients: list = None
):
    """
    Print the discovered Wi-Fi networks in a formatted table. If in handshake mode,
    print the captured handshake information in a formatted table.

    Args:
        mode (str): Mode of operation, either "scan" or "handshake".
        data (dict): Dictionary containing network or handshake information.
        bssid (str): BSSID of the target access point.
        channel (int): Channel of the target access point.
        clients (list): List of client MAC addresses (for handshake mode).
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
        print("─" * 55)
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
            print("\nAwaiting handshake packets... ")
            print("\nTry a deauth on broadcast or one of these devices:")

            if clients:
                for i, client in enumerate(clients, 1):
                    print(f"   {i}. {client}")

            else:
                print("   No devices detected yet.")
