# Installing Hybrid IDS

Pick the row that matches your machine.

| Your OS | Fastest path | Python needed? |
|---|---|---|
| **Windows 10/11 (64-bit)** | `HybridIDS.exe` from [Releases](https://github.com/Unspeakable149/Major-Project-Final/releases) — double-click | No |
| **macOS** | Clone the repo, `python3 run_hybrid_ids.py` | Yes |
| **Linux** | Clone the repo, `python3 run_hybrid_ids.py` | Yes |

---

## Step 0 — install Wireshark first (every platform)

Wireshark's `tshark` is the packet-capture engine. It is **not pip-installable**,
and nothing works without it.

| | |
|---|---|
| **Windows** | https://www.wireshark.org/download.html — keep the defaults, including **Npcap**. That is the capture driver. |
| **macOS** | `brew install --cask wireshark`, or install Wireshark.app |
| **Debian / Ubuntu** | `sudo apt install tshark` |
| **Fedora** | `sudo dnf install wireshark-cli` |

`tshark` does not need to be on your `PATH` — the app looks in the standard
install locations too.

---

## Windows — the prebuilt app

1. Install Wireshark (step 0).
2. Download `HybridIDS.exe` from [Releases](https://github.com/Unspeakable149/Major-Project-Final/releases).
3. Double-click it. Approve the Administrator prompt — live packet capture and the
   firewall-block feature both require it.
4. The app opens in its own window. Close the window to shut everything down.

**Requirements**

| | |
|---|---|
| OS | Windows 10 version 1607 or newer, or Windows 11 |
| Architecture | 64-bit Intel/AMD (`x64`). Runs on ARM64 Windows through emulation. |
| Not supported | Windows 7, 8, 8.1 and all 32-bit Windows — the app is built with Python 3.14, which dropped them |
| Also needs | Wireshark/tshark, and the Edge WebView2 Runtime (ships with Windows 11) |
| Free disk | ~1.5 GB. The exe is ~380 MB and unpacks to about 1 GB of temp space while running — PyTorch and SHAP are inside it, so the LSTM layer and the explainability charts work with nothing else installed. |

Your antivirus may flag the download. It is an unsigned PyInstaller binary, which
is a well-known false positive. The SHA-256 of every release asset is published
alongside it — verify it if you would rather not take that on trust.

---

## Any OS — from source

```bash
git clone https://github.com/Unspeakable149/Major-Project-Final.git
cd Major-Project-Final
python -m pip install -r requirements.txt
```

Then, as an administrator:

```bash
# Windows — from an Administrator terminal
python run_hybrid_ids.py

# macOS / Linux
sudo python3 run_hybrid_ids.py
```

The dashboard opens on `http://127.0.0.1:8501`.

On Windows you can also just double-click **`START.bat`**, which self-elevates and
starts the capture backend and the dashboard together.

### Launcher flags

| Flag | Effect |
|---|---|
| `--no-capture` | Dashboard only — no packet capture, no admin rights needed. Use this to browse saved results. |
| `--port 8600` | Move the dashboard off the default port |

---

## Why there is no ready-made macOS or Linux download

The `.exe` is produced by **PyInstaller, which cannot cross-compile.** A macOS
binary has to be built on macOS and a Linux binary on Linux; there is no way to
produce either from a Windows machine, and a Linux build is additionally tied to
the glibc version of the machine that built it.

So those platforms get the source plus a one-command build script instead. To
build a native binary:

```bash
cd APP
chmod +x build_unix.sh
./build_unix.sh
sudo ./dist/HybridIDS
```

On macOS this also produces `dist/HybridIDS.app`. You can skip building entirely
and run `run_hybrid_ids.py` directly — same engine, opens in your browser instead
of its own window.

### What has actually been tested

| Platform | Status |
|---|---|
| **Windows 10/11 x64** | **Verified.** The `.exe` was built and driven end to end — the dashboard renders with no errors and the capture backend classifies live traffic. |
| **Linux (Ubuntu 24.04, Python 3.12)** | **Verified from source.** Clean `pip install`, all imports, tshark discovery, the alert schema, the LSTM fusion logic, the v2 test suite, and a full dashboard render (132 elements, 0 exceptions). The native `build_unix.sh` binary was **not** built here. |
| **macOS** | **Not tested.** No Mac was available, and PyInstaller cannot cross-compile. The code path is shared with the Linux one that does work, so it is likely fine — but treat first run as unverified. |

---

## Avoiding `sudo` on Linux

Grant the capture helper the capability once, and the app no longer needs root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(which dumpcap)"
```

---

## What differs by platform

Everything runs everywhere — capture, all detection layers, threat scoring,
alerting, reports, PCAP analysis — **except the firewall "Block IP" buttons**,
which shell out to Windows' `netsh advfirewall`. On macOS and Linux those buttons
report themselves as unsupported rather than silently failing.

---

## Optional configuration

Both are off until you create them, and the app runs normally without either.

| File | Copy from | Purpose |
|---|---|---|
| `Aalok/Dashboard/notifier_config.json` | `notifier_config.json.example` | Push Severe alerts to email / Discord / Slack |
| `Aalok/Dashboard/baseline.txt` | `baseline.txt.example` | Known-good IPs (your gateway, DNS) auto-classified safe, suppressing false positives |

**`notifier_config.json` stores its SMTP password in clear text** — SMTP AUTH
needs the original secret, so there is no way around it. Use a throwaway or
app-specific password, and never share a filled-in copy. Both files are
gitignored.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Wireshark is required but was not found" | Install Wireshark, then re-run |
| Dashboard is empty on first open | Expected — no alert database ships. Let a capture run for a minute. |
| No traffic appears | Not running elevated, or the wrong interface was auto-detected |
| Window never appears (Windows exe) | WebView2 missing — it falls back to your browser. Check `%LOCALAPPDATA%\HybridIDS\desktop_server.log`. |
| Antivirus flags the exe | Unsigned PyInstaller binary — known false positive |
| Model loads but scores nonsense | scikit-learn version drift. The shipped models are pickled with 1.8.0; `requirements.txt` pins it for that reason. Retrain if you change the pin. |

---

Next: **[USAGE.md](USAGE.md)** — what the tabs do and how to read an alert.
