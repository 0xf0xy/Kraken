<h1 align="center">KRAKEN</h1>

<p align="center">
  <em>wpa/wpa2 audit toolkit</em>
</p>

<p align="center">
  <img src="https://img.shields.io/github/release/0xf0xy/Kraken?color=AAAAAA&style=for-the-badge&labelColor=111111"/>
  <img src="https://img.shields.io/badge/python-3.10+-AAAAAA?style=for-the-badge&logo=python&logoColor=FFFFFF&labelColor=111111"/>
  <img src="https://img.shields.io/github/license/0xf0xy/Kraken?color=AAAAAA&style=for-the-badge&labelColor=111111"/>
</p>

<br>

> [!WARNING]
>
> **Kraken is intended for educational, research, and authorized security testing purposes only.**
>
> Wireless operations should only be performed against networks and devices where you have explicit permission to perform security testing.
>
> The author is not responsible for misuse of this software.

<br>

## > Overview

**Kraken** is a modular wireless security auditing toolkit focused on WPA/WPA2 networks.

Kraken supports:

* Wireless interface management
* Monitor-mode setup and restoration
* Wireless network discovery
* WPA/WPA2 4-way handshake capture
* Deauthentication frame transmission
* Offline handshake verification with wordlists

Kraken was built primarily as a learning and security research project around:

* Wireless protocol analysis
* WPA/WPA2 authentication research
* Controlled wireless security testing
* CLI application design
* Modular Python architecture

<br>

## > How It Works

Kraken follows the WPA/WPA2 authentication exchange and stores the values
needed for offline verification.

First, Kraken places the wireless adapter in monitor mode and scans beacon
frames to identify access points, channels, signal strength, and encryption.

When a target is selected, Kraken tunes the adapter to its channel and listens
for the 4-way handshake:

1. The access point sends message 1 with the `ANonce`.
2. The client responds with message 2 containing the `SNonce` and `MIC`.
3. Kraken records the EAPOL frame and the addresses of the access point and client.
4. The captured values are written to `handshake.json`.

If the client does not reconnect by itself, a deauthentication request can be
used during an authorized test to make it authenticate again:

```bash
sudo kraken deauth -i mon0 -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 -p 10
```

The `crack` operation does not transmit packets. For each word in the supplied
wordlist, Kraken derives the WPA/WPA2 key material from the SSID, both nonces,
and both MAC addresses, then compares the calculated MIC with the captured
MIC. A matching MIC confirms the candidate password.

The SSID is collected from a beacon or probe response because EAPOL frames do
not contain the network SSID.

<br>

## > Audit Operations

| Operation | Description |
| --------- | ----------- |
| `start`   | Creates a monitor-mode interface. |
| `stop`    | Restores the interface to managed mode. |
| `dump`    | Discovers networks or captures a selected handshake. |
| `deauth`  | Sends deauthentication frames to an authorized client. |
| `crack`   | Tests a captured handshake against a wordlist. |

<br>

## > Installation

### Requirements

* Python 3.10+
* `pip`
* Root privileges for wireless operations
* Wireless adapter with monitor-mode support
* `iw`, `ip`, `systemctl`, and a wireless network manager

Clone the repository:

```bash
git clone https://github.com/0xf0xy/Kraken.git
cd Kraken
```

Install Kraken:

```bash
pip install .
```

Verify the installation:

```bash
kraken -h
```

<br>

## > Usage

Provide the command and options for the desired operation:

```bash
sudo kraken <command> [options]
```

For all available commands:

```bash
kraken -h
```

For all available options for a command:

```bash
kraken <command> -h
```

<br>

## > Project Status

Kraken is an experimental project focused on wireless security research,
experimentation, and learning.

The project is under active development and its architecture and behavior may
change between releases.

<br>

---

<p align="center">
  <a href="https://github.com/0xf0xy"><b>0xf0xy</b></a> •
  <a href="./LICENSE"><b>MIT License</b></a>
</p>
