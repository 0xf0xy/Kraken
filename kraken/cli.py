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

from kraken.core import Kraken
import argparse
import os


def build_parser():
    parser = argparse.ArgumentParser(
        description="Kraken: WPA/WPA2 audit toolkit",
        epilog="You need root privileges to run this tool.",
        add_help=False,
    )

    subparsers = parser.add_subparsers(title="Modes", dest="command")

    start = subparsers.add_parser("start", help="Start monitor mode on an interface")
    start.add_argument(
        "-i", "--iface", required=True, help="Interface to set in monitor mode"
    )

    stop = subparsers.add_parser("stop", help="Stop monitor mode on an interface")
    stop.add_argument(
        "-i", "--iface", required=True, help="Interface to stop monitor mode"
    )

    dump = subparsers.add_parser(
        "dump",
        help="Dump networks and clients. If BSSID and channel is provided, capture handshakes for that network",
    )
    dump.add_argument("-i", "--iface", required=True, help="Interface in monitor mode")
    dump.add_argument(
        "-b", "--bssid", type=str.lower, help="BSSID of the target network (optional)"
    )
    dump.add_argument("-c", "--channel", type=int, help="Channel to scan (optional)")

    deauth = subparsers.add_parser(
        "deauth", help="Send deauthentication packets to a target"
    )
    deauth.add_argument(
        "-i", "--iface", required=True, help="Interface in monitor mode"
    )
    deauth.add_argument(
        "-b", "--bssid", required=True, help="BSSID of the target network"
    )
    deauth.add_argument(
        "-c", "--client", default="", help="Client MAC address (optional)"
    )
    deauth.add_argument(
        "-p", "--packets", type=int, default=10, help="Deauth packets (default: 10)"
    )

    crack = subparsers.add_parser(
        "crack", help="Crack WPA/WPA2 handshakes captured with Kraken"
    )
    crack.add_argument("-w", "--wordlist", required=True, help="Wordlist")
    crack.add_argument("-f", "--file", required=True, help="Handshake JSON file")

    meta = parser.add_argument_group("Information")
    meta.add_argument("-h", "--help", action="help", help="Show this help menu")
    meta.add_argument(
        "-v",
        "--version",
        action="version",
        version="Kraken v1.0.0",
        help="Show program version",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not os.geteuid() == 0:
        parser.error("you must run this tool with root privileges.")

    kraken = Kraken()

    if args.command == "start":
        kraken.start_monitor(args.iface)

    elif args.command == "stop":
        kraken.stop_monitor(args.iface)

    elif args.command == "dump":
        kraken.dump_networks(args.iface, args.bssid, args.channel)

    elif args.command == "deauth":
        kraken.deauth(args.iface, args.bssid, args.client, args.packets)

    elif args.command == "crack":
        kraken.crack_handshake(args.wordlist, args.file)
