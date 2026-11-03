# HomeSIEM

A small, lightweight security dashboard for a home network. It runs as **one file** with nothing else to
install, on Windows, Linux (including Raspberry Pi) and macOS. It is made to work on weak hardware such as a
Raspberry Pi or an old Core 2 Duo PC with 2 GB of RAM.

## What it does

| Feature | What you get | Needs |
|---|---|---|
| **Devices** | Finds every device on your network (20 at a time), with name, vendor and when it was last seen. Alerts when a new one joins. | any computer |
| **Open ports** | Scans devices for open ports, names the service and reads its banner. Flags risky ones (Telnet, FTP, remote desktop...). | any computer |
| **Traffic** | Live download/upload chart, top devices, top remote hosts. Reads packet headers only; nothing is stored. | Linux, and a computer that sees the traffic |
| **Rules and alerts** | Port scans, ARP spoofing, unusual bandwidth, new destinations, log patterns. Notifications to Telegram, a webhook or email. | rules need the feature they watch |
| **Logs** | Receives syslog from routers and other machines, searchable. A built-in agent sends log files from any computer. | any computer |
| **Access control** | Block a device or limit its speed. | Linux, root or `CAP_NET_ADMIN`, and the computer must be your network's **gateway** |
| **Sign-in and HTTPS** | Password, lock-out after wrong guesses, encrypted dashboard. | included |

## Quick start

### A. Try it on your own computer (no install)

1. Copy the file for your computer from the `dist` folder (for example `homesiem-windows.exe`).
2. Run it from a terminal:
   * Windows (PowerShell): `.\homesiem-windows.exe -capture demo`
   * Linux: `chmod +x homesiem-linux` then `sudo ./homesiem-linux`
3. A **setup code** is printed in the window. Open `http://127.0.0.1:8080`, enter the code and choose a password (at least 10 characters).

`-capture demo` fills the Traffic page with simulated traffic. Windows and macOS cannot capture real traffic yet.

### B. Keep it running on a Linux computer or Raspberry Pi

```bash
sudo ./deploy/install-linux.sh ./homesiem-linux        # on a 64-bit Pi use ./homesiem-pi-arm64
sudo cat /var/lib/homesiem/setup-code.txt              # your setup code
```

Then open `https://THIS-COMPUTER:8080`. It starts at boot and restarts if it crashes. It runs as its own
unprivileged user with only the three permissions it needs.

### C. Keep it running on Windows

In an **administrator** PowerShell, in the folder with the file: `.\deploy\install-windows.ps1`

## First sign-in and HTTPS

* The first start has no password. A one-time **setup code** appears in the start-up output and in the file
  `setup-code.txt` next to the database. Anyone who can reach the dashboard before you cannot take it over without that code.
* When the dashboard can be reached from other computers (`-addr 0.0.0.0:8080`), HTTPS is switched on automatically
  with a self-signed certificate. **Your browser will warn once.** To be sure it is your own HomeSIEM, compare the
  fingerprint it shows with the line `HTTPS certificate fingerprint` in the start-up output, then continue.
* Five wrong passwords from one address lock that address for 15 minutes and raise an alert.
* Forgot the password? On the HomeSIEM computer: `homesiem passwd -db /path/to/homesiem.db`.

## Commands

| Command | What it does |
|---|---|
| `homesiem` | Runs the dashboard. |
| `homesiem agent -server HOST:514 -file /var/log/auth.log` | Sends the new lines of log files to a HomeSIEM computer. Works on any computer. |
| `homesiem passwd` | Sets a new dashboard password. |
| `homesiem unblock` | Emergency exit: removes every block and speed limit. Run with sudo. |
| `homesiem bench` | Measures how fast this computer is, to see if it can keep up with your network. |
| `homesiem -version` | Shows the version. |

## Settings (flags)

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `127.0.0.1:8080` | Where the dashboard listens. `0.0.0.0:8080` lets other computers in. |
| `-tls` | `auto` | `auto` = HTTPS whenever other computers can reach it; `self`; `off` |
| `-tls-cert`, `-tls-key` | | Use your own certificate. |
| `-no-auth` | off | No sign-in. Only allowed with `-addr 127.0.0.1:...`. |
| `-db` | `homesiem.db` | Database file. |
| `-rules` | `rules.yaml` | Alert rules and notification settings (created on first start). |
| `-iface` | automatic | Network interface to scan. |
| `-oui` | | A complete vendor list (IEEE `oui.csv`) for the Vendor column. |
| `-scan-interval` | `60` | Seconds between device scans. |
| `-workers` | `20` | Devices probed at the same time. |
| `-port-interval` | `360` | Minutes between automatic port scans (`0` = only on request). |
| `-port-rate`, `-port-conc` | `200`, `10` | Port scan speed limits. |
| `-capture` | `auto` | `auto`, `off` or `demo`. |
| `-capture-iface`, `-promisc` | | Interface for capture; promiscuous mode for a mirror port. |
| `-flow-interval`, `-flow-rows`, `-max-flows` | `60`, `500`, `20000` | Traffic summary sizes. |
| `-enforce` | `auto` | Blocking: `auto`, `dry-run` or `off`. |
| `-release-on-exit` | off | Remove blocks when HomeSIEM stops. |
| `-syslog` | `0.0.0.0:514` | Where logs are received (`off` to disable; falls back to 5514 without root). |
| `-syslog-allow`, `-syslog-rate` | private networks, `200` | Who may send logs, and a limit per sender. |
| `-log-days`, `-log-max-rows` | `7`, `100000` | How long and how much received log is kept. |
| `-retain-days`, `-retain-alert-days`, `-retain-flow-hours` | `7`, `30`, `24` | How long events, alerts and traffic summaries are kept. |
| `-mem-limit` | `200` | Soft memory limit in MB (`0` = none). |

## Files it creates (next to the database)

`homesiem.db` (all data), `rules.yaml` (**may contain tokens and passwords: keep it private**),
`homesiem-cert.pem` and `homesiem-key.pem` (HTTPS), and `setup-code.txt` (only until the password exists).
**Backup:** stop HomeSIEM and copy `homesiem.db` and `rules.yaml`.

## Network ports

* TCP **8080**: dashboard (`-addr`).
* UDP and TCP **514**: incoming logs (5514 if 514 is not allowed).

## Where to put it

Device discovery, port scans, logs and alerts work from any computer on the network. Two features need HomeSIEM to
sit **in the path** of the traffic, which means it must be your network's **gateway** (a Linux computer or Pi between
your router and your devices) or sit on a switch's mirror port:

* seeing other devices' traffic (the Traffic page), and
* blocking devices or limiting their speed.

A HomeSIEM computer that is just another device on the network sees only its own traffic.

## Security notes

* Do not forward the dashboard port to the internet. Keep it on your private network.
* Passwords are stored as salted PBKDF2-SHA256 hashes. Sessions end after 12 hours without use.
* Log text, device names and banners come from other machines, so the dashboard only ever shows them as plain text.
* Syslog has no login. By default only private-network addresses may send logs, each with a rate limit.
* Only scan and monitor networks that you own or have permission to test.

## Updating

Replace the program file and restart it. The database upgrades itself. Back up first.

## Uninstalling

* Linux: `sudo ./deploy/uninstall-linux.sh` (add `--purge` to delete the data too).
* Windows (administrator PowerShell): `.\deploy\uninstall-windows.ps1` (add `-Purge` to delete the data too).

## Troubleshooting

| Problem | Try |
|---|---|
| The browser says the connection is not private | Normal for the self-signed certificate. Compare the fingerprint, then continue. |
| `http://...` stops working after an upgrade | The dashboard now uses `https://` whenever other computers can reach it. |
| Only your own device appears | The computer is on a different network (a VM using NAT, or Wi-Fi client isolation). Use `-iface`. |
| The Traffic page is grey | Capture needs Linux and `sudo` (or `CAP_NET_RAW`). |
| Blocking does nothing | The computer must be the gateway, and `ip_forward` must be on. The Devices page banner says so. |
| Locked out after wrong passwords | Wait 15 minutes, or use `homesiem passwd` on the HomeSIEM computer. |
| Everything is blocked by mistake | `sudo homesiem unblock`, or the **Release everyone** button. |
| Is this computer fast enough? | Run `homesiem bench`. |

## Known limits

* Live capture is Linux only. Windows and macOS can use `-capture demo`.
* IPv6 internet traffic is counted as "Other"; IPv4 is fully classified.
* Speed limits drop packets above the rate rather than shaping smoothly.
* Windows Event Log is not collected; the agent reads text files.
* Very busy networks (near 100 Mbit/s sustained) may need a faster computer than a Core 2 Duo for live capture.
