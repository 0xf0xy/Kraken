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
        description="Kraken: ",
        epilog="You need root privileges to run this tool.",
        add_help=False,
    )

    mode = parser.add_argument_group("Mode Settings")
    mode.add_argument("--monitor", help="Network interface to use")
    mode.add_argument("--sniff", help="")
    mode.add_argument("--deauth", help="")
    mode.add_argument("--crack", help="")

    target = parser.add_argument_group("Target Settings")
    target.add_argument("-b", "--bssid", help="")
    target.add_argument("-c", "--channel", help="")

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
