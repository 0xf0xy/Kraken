import pyric.pyw as pyw
import subprocess
import threading
import time
import random
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, EAPOL, wrpcap, rdpcap
import os

hopper_stop_event = threading.Event()
networks = {}


def stop_network_services():
    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
    except subprocess.CalledProcessError:
        return

    try:
        subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=True)
    except subprocess.CalledProcessError:
        return


def start_network_services():
    subprocess.run(["systemctl", "start", "wpa_supplicant"])
    subprocess.run(["systemctl", "start", "NetworkManager"])


def is_monitor_mode(interface):
    try:
        card = pyw.getcard(interface)
        mode = pyw.modeget(card)
        return mode == "monitor"
    except Exception as e:
        print(f"[x] Erro ao verificar o modo da interface: {e}")
        return False


def set_monitor_mode(interface):
    try:
        stop_network_services()
        card = pyw.getcard(interface)
        print(f"[*] Colocando interface {interface} em modo monitor...")

        pyw.down(card)
        pyw.modeset(card, "monitor")
        pyw.up(card)

    except Exception as e:
        print(f"[x] Erro ao configurar interface: {e}")
        return None


def restore_interface(interface):
    try:
        card = pyw.getcard(interface)
        print(f"[*] Restaurando interface {interface} para modo managed...")
        pyw.down(card)
        pyw.modeset(card, "managed")
        pyw.up(card)
        start_network_services()

    except Exception as e:
        print(f"[x] Erro ao restaurar interface: {e}")


def set_channel(interface, channel):
    try:
        card = pyw.getcard(interface)
        pyw.chset(card, channel)

    except Exception as e:
        print(f"[x] Erro ao mudar canal: {e}")


def channel_hopper(interface, delay=1.0):
    def hop():
        channels = list(range(1, 14))
        while not hopper_stop_event.is_set():
            channel = random.choice(channels)
            set_channel(interface, channel)
            time.sleep(delay)

    thread = threading.Thread(target=hop, daemon=True)
    thread.start()
    return thread


def clear_screen():
    os.system("clear")


def get_encryption(pkt):
    # Detecta tipo de criptografia (simplificado)
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split("+")
    if "privacy" in cap:
        # WPA ou WPA2
        if pkt.haslayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48:
                    return "WPA2"
                if elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
                    return "WPA"
                elt = elt.payload.getlayer(Dot11Elt)
        return "WEP"
    else:
        return "Open"


def print_networks():
    clear_screen()
    print("ID  BSSID              CH  PWR  ENC   BEAC  ESSID")
    print("-" * 75)
    for idx, (bssid, info) in enumerate(networks.items(), 1):
        ssid = info["ssid"] if info["ssid"] else "<oculta>"
        print(
            f"[{idx:<2}] {bssid:<18} {info['channel']:<3} {info['signal']:<4} {info['encryption']:<5} {info['beacons']:<5} {ssid}"
        )


def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = (
            pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else ""
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
        print_networks()


def passive_capture(iface):
    channel_hopper(iface)
    print(f"[*] Iniciando escuta passiva em {iface}...")

    sniff(iface=iface, prn=packet_handler, store=0)

    print(f"\r\033[K\n[+] Captura finalizada.")


def select_network():
    print_networks()
    escolha = int(input("Escolha o ID da rede para capturar handshake: "))
    bssids = list(networks.keys())
    return bssids[escolha - 1]


def capture_handshake(interface, bssid, channel, timeout=15):
    set_channel(interface, channel)
    print(f"\r\033[KMonitorando {bssid} no canal {channel} para handshake...")

    handshakes = []

    def handshake_filter(pkt):
        return (
            pkt.haslayer(EAPOL)
            and pkt.haslayer(Dot11)
            and (pkt.addr1 == bssid or pkt.addr2 == bssid)
        )

    sniff(
        iface=interface,
        lfilter=handshake_filter,
        timeout=timeout,
        store=True,
        prn=lambda x: handshakes.append(x),
    )

    if handshakes:
        filename = "handshake.cap"
        wrpcap(filename, handshakes)
        print(
            f"\r\033[K[+] {len(handshakes)} pacotes EAPOL capturados e salvos em {filename}!"
        )

    else:
        print("\r\033[K[!] Handshake não encontrado no tempo limite.")
