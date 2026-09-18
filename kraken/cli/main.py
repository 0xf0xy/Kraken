import argparse
from importlib.metadata import version
import os
import subprocess
from typing import Any

from kraken.core.engine import Kraken
from kraken.core.models import Network
from kraken.services.wireless import WirelessError


def _clear_terminal() -> None:
    subprocess.run(["clear"], check=False)


def red(text: str) -> str:
    return f"\033[1;31m{text}\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kraken: WPA/WPA2 audit toolkit",
        epilog="You need root privileges to run this tool.",
    )

    subparsers = parser.add_subparsers(
        title="Modes",
        dest="command",
    )

    start = subparsers.add_parser(
        "start",
        help="Start monitor mode on an interface",
    )
    start.add_argument(
        "-i",
        "--iface",
        required=True,
        help="Interface to set in monitor mode",
    )

    stop = subparsers.add_parser(
        "stop",
        help="Stop monitor mode on an interface",
    )
    stop.add_argument(
        "-i",
        "--iface",
        required=True,
        help="Interface to stop monitor mode",
    )

    dump = subparsers.add_parser(
        "dump",
        help=(
            "Dump networks and clients. If BSSID and channel are provided, "
            "capture handshakes for that network"
        ),
    )
    dump.add_argument(
        "-i",
        "--iface",
        required=True,
        help="Interface in monitor mode",
    )
    dump.add_argument(
        "-b",
        "--bssid",
        type=str.lower,
        help="BSSID of the target network (optional)",
    )
    dump.add_argument(
        "-c",
        "--channel",
        type=int,
        help="Channel to scan (optional)",
    )

    deauth = subparsers.add_parser(
        "deauth",
        help="Send deauthentication packets to a target",
    )
    deauth.add_argument(
        "-i",
        "--iface",
        required=True,
        help="Interface in monitor mode",
    )
    deauth.add_argument(
        "-b",
        "--bssid",
        required=True,
        help="BSSID of the target network",
    )
    deauth.add_argument(
        "-c",
        "--client",
        default="",
        help="Client MAC address (optional)",
    )
    deauth.add_argument(
        "-p",
        "--packets",
        type=int,
        default=10,
        help="Deauth packets (default: 10)",
    )

    crack = subparsers.add_parser(
        "crack",
        help="Crack WPA/WPA2 handshakes captured with Kraken",
    )
    crack.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Wordlist",
    )
    crack.add_argument(
        "-f",
        "--file",
        required=True,
        help="Handshake JSON file",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"Kraken v{version('kraken')}",
        help="Show program version",
    )

    return parser


def display_networks(networks: dict[str, Network]) -> None:
    _clear_terminal()
    print(" ESSID                     | BSSID             | ENC   | CH  | PWR   | BEAC")
    print("─" * 75)

    for bssid, network in networks.items():
        print(
            f" {network.ssid or '<hidden>':25} | {bssid} | "
            f"{network.encryption:<5} | {network.channel!s:<3} | "
            f"{network.signal!s:<5} | {network.beacons:<6}"
        )

    print("─" * 75)


def display_handshake(capture: Any, channel: int) -> None:
    _clear_terminal()
    print(f"BSSID     : {capture.target_bssid}")
    print(f"Channel   : {channel}")
    print("─" * 55)
    print("EAPOL Packets:")

    fields = (
        ("anonce", "Packet 1 (ANonce)"),
        ("snonce", "Packet 2 (SNonce)"),
        ("mic", "Packet 3 (MIC)"),
        ("eapol", "Packet 4 (Full Frame)"),
    )

    for field, label in fields:
        marker = f"[{red('+')}]" if getattr(capture, field) else f"[{red('x')}]"
        print(f"   • {marker} {label}")

    if capture.complete:
        print(f"\n{red('Valid 4-Way Handshake Captured!')}")

    else:
        print("\nAwaiting handshake packets...")

    print("\nTry a deauth in one of these devices:")

    for index, client in enumerate(sorted(capture.clients), 1):
        print(f"   {index}. {client}")

    if not capture.clients:
        print("   No devices detected yet.")


def display_deauth(bssid: str, client: str, packets: int) -> None:
    target = client.upper() if client else "FF:FF:FF:FF:FF:FF"
    print(f"Sending deauth to '{target}' | AP: {bssid.upper()}")
    print(f"Packets: {packets}")


def display_crack(result: str | None) -> None:
    if result:
        print(f"[{red('+')}] Key found: {red(result)}")

    else:
        print(f"[{red('x')}] No key found.")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if os.geteuid() != 0:
        parser.error("you must run this tool with root privileges.")

    try:
        if args.command == "start":
            monitor_interface = Kraken().wireless.start_monitor(args.iface)
            print(f"[{red('+')}] Interface '{args.iface}' is on ({monitor_interface})")
            return

        if args.command == "stop":
            managed_interface = Kraken().wireless.stop_monitor(args.iface)
            print(f"[{red('+')}] Interface '{args.iface}' is off ({managed_interface})")
            return

        kraken = Kraken()

        if args.command == "dump":
            kraken.dump_networks(
                args.iface,
                args.bssid,
                args.channel,
                network_callback=display_networks,
                handshake_callback=lambda capture: display_handshake(
                    capture, args.channel
                ),
            )
            return

        if args.command == "deauth":
            display_deauth(args.bssid, args.client, args.packets)
            kraken.send_deauth(args.iface, args.bssid, args.client, args.packets)
            return

        if args.command == "crack":
            display_crack(kraken.crack_handshake(args.wordlist, args.file))
            return

    except KeyboardInterrupt:
        return

    except WirelessError as exc:
        print(f"{red('[x]')} {exc}")
        raise SystemExit(1)

    except ValueError as exc:
        print(f"{red('[x]')} {exc}")
        raise SystemExit(1)
