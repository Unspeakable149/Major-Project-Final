# Hybrid IDS — how to run it on your machine

Two ways to run the same app. Pick the row that matches your computer.

| Your OS | What to use | Build needed? |
|---|---|---|
| **Windows 10/11 (64-bit)** | `Windows/HybridIDS.exe` — double-click | No |
| **macOS** | `macOS-Linux/` → run `./build_unix.sh`, or just `python3 run_hybrid_ids.py` | Yes, on your Mac |
| **Linux** | `macOS-Linux/` → run `./build_unix.sh`, or just `python3 run_hybrid_ids.py` | Yes, on your PC |

---

## Why there is no ready-made Mac or Linux download

The `.exe` is produced by **PyInstaller, which cannot cross-compile.** A macOS
binary has to be built on macOS and a Linux binary on Linux — there is no way to
produce either from a Windows machine. A Linux build is additionally tied to the
glibc version of the machine that built it.

So the folder ships the **source bundle plus a one-command build script** for
those platforms instead. Anyone on a Mac or Linux box gets a native binary by
running one script, and can skip building entirely by launching the Python
script directly.

**What has actually been tested**

| Platform | Status |
|---|---|
| **Windows 10/11 x64** | **Verified.** The `.exe` was built and driven end to end — the dashboard renders with no errors and the capture backend classifies live traffic. |
| **Linux (Ubuntu 24.04, Python 3.12)** | **Verified from source.** Clean `pip install`, all imports, tshark discovery, the alert schema, the LSTM fusion logic, the v2 test suite, and a full dashboard render (132 elements, 0 exceptions). The native `build_unix.sh` binary was **not** built here. |
| **macOS** | **Not tested.** No Mac was available, and PyInstaller cannot cross-compile. The code is shared with the Linux path that does work, so it is likely fine — but treat first run as unverified. |

---

## Windows — `Windows/HybridIDS.exe`

1. Install **Wireshark** first: https://www.wireshark.org/download.html
   (keep the default options, including **Npcap** — that is the capture driver).
2. Double-click `HybridIDS.exe`. Approve the Administrator prompt — live packet
   capture and the firewall-block feature both require it.
3. The app opens in its own window. Close the window to shut everything down.

**Requirements**

| | |
|---|---|
| OS | Windows 10 version 1607 or newer, or Windows 11 |
| Architecture | 64-bit Intel/AMD (`x64`). Runs on ARM64 Windows through emulation. |
| Not supported | Windows 7, 8, 8.1, and all 32-bit Windows — the app is built with Python 3.14, which dropped those. |
| Also needs | Wireshark/tshark, and the Edge WebView2 Runtime |

WebView2 ships with Windows 11 and with most Windows 10 installs. If it is
missing, the app now says so and **opens in your normal browser instead** rather
than failing — so it still works either way.

First launch takes a few seconds: the single file unpacks itself to a temp
folder. If antivirus quarantines it, that is the usual unsigned-PyInstaller
false positive; allow the file and re-run.

---

## macOS and Linux — `macOS-Linux/`

### Option A — no build, just run it

```bash
cd macOS-Linux
python3 -m pip install -r requirements.txt
sudo python3 run_hybrid_ids.py
```

The dashboard opens in your browser. This is the quickest path and needs no
PyInstaller.

### Option B — build a native binary

```bash
cd macOS-Linux
chmod +x build_unix.sh
./build_unix.sh
sudo ./dist/HybridIDS
```

On macOS this also produces `dist/HybridIDS.app`.

### Installing tshark

| | |
|---|---|
| macOS | `brew install --cask wireshark` (or install Wireshark.app) |
| Debian/Ubuntu | `sudo apt install tshark` |
| Fedora | `sudo dnf install wireshark-cli` |

### Why `sudo`

Opening a network interface in promiscuous mode is privileged on every OS. To
avoid `sudo` on Linux, grant the capture helper the capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(which dumpcap)"
```

### What differs on macOS/Linux

Everything runs — capture, all detection layers, threat scoring, alerting,
reports, PCAP analysis — **except the firewall "Block IP" buttons**, which shell
out to Windows' `netsh advfirewall`. On other platforms those buttons report
that they are unsupported instead of failing. Run with `--no-capture` to browse
saved results without root.

---

## What is inside `macOS-Linux/`

The repository's one-folder-per-contributor layout is preserved, so the code
reads the same way it does in the project itself:

```
macOS-Linux/
├── Aalok/Dashboard/   SOC dashboard, detection engine, fusion, scoring, models
├── Aaron/             MITRE ATT&CK mapping
├── Megan/             LSTM sequence model, SHAP explainability, retraining
├── Rui Yang/          PCAP forensic engine, GeoIP threat map, reports
├── run_hybrid_ids.py  cross-platform launcher
├── build_unix.sh      native macOS/Linux build
└── requirements.txt
```

The launcher finds `Aalok/Dashboard` automatically and also accepts a flattened
`Dashboard/` layout, so moving folders around will not break it.

## Privacy — what this download does NOT contain

This release is built to be handed to people outside the team, so everything
tied to the machine that built it has been stripped and verified absent:

- **No alert database.** `ids_logs.db` holds real captured traffic. Excluded from
  both the `.exe` and the source bundle; recreated empty on first run.
- **No `retrain_state.json`.** It stored absolute model-version paths that
  embedded the builder's username and folder tree.
- **No `ai_ready_advanced_flows.csv`.** It held engineered rows from a real
  capture, public source IPs included. Only the offline training scripts ever
  read it, never the running app.
- **No credentials.** Only `notifier_config.json.example` with placeholders ships.
- **No compiled bytecode / packet captures.** No `__pycache__`, `.pyc` or `.pcap`.
- **The threat-intel feed uses RFC 5737 documentation addresses**
  (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) — not real hosts.

Verified by decompressing every entry inside the `.exe` and scanning the source
bundle, including all model binaries, for home-directory paths and usernames.

## The dashboard starts empty — that is expected

Neither download ships an alert database. `ids_logs.db` would otherwise contain
real captured traffic (local IP addresses, ports, timings) from the machine that
built the release, so it is deliberately excluded from both the `.exe` and the
source bundle. The app creates an empty one with the right schema on first run.

So the first time you open it, the tables and charts are blank. Let a capture run
for a minute and alerts start appearing. To browse without capturing anything,
start it with `--no-capture` — you will get an empty but fully working dashboard.

Note that the Windows `.exe` keeps its database inside the temporary folder it
unpacks itself into, which Windows removes when the app closes — so alerts do
not carry over between runs of the exe. Run from source (the `macOS-Linux`
bundle works on Windows too) if you need the log to persist.

## Security notes — read before running

**Only run this on a network you are authorised to monitor.** It captures and
inspects live packet traffic. Doing that on a network you do not own or have
permission to test may be illegal where you live.

**It runs elevated.** Administrator on Windows, root on macOS/Linux. Packet
capture and firewall changes both require it. That is a genuine level of trust
to extend to any program — the full source sits next to the binary in
`macOS-Linux/`, so read it before you run it if you would rather not take the
`.exe` on faith. Better still, build it yourself with `build_unix.sh`.

**No authentication.** The dashboard binds to `127.0.0.1` only and is not
reachable from the network. That loopback binding is the *only* thing keeping it
private — anyone who can reach the port gets full control, including firewall
blocking. Do not change `server.address`, do not port-forward it, and do not run
it on a shared/multi-user machine you do not trust.

**The firewall buttons really change your firewall.** "Block IP" installs a
Windows Defender rule named `IDS_BLOCK_<ip>`. Remove them from the dashboard, or
with `netsh advfirewall firewall delete rule name=IDS_BLOCK_<ip>`.

**Credentials are stored in clear text.** If you enable email/Discord/Slack
alerts, `notifier_config.json` holds the SMTP password and webhook URLs
unencrypted — SMTP AUTH needs the original secret, so there is no way around
that. The file is written owner-only (`0600`); note that on **Windows** this is
best-effort, because `chmod` there only toggles the read-only attribute instead
of applying a real ACL. Never commit or share a filled-in copy. Use a
throwaway/app-specific password, not your main one.

**The `.exe` is not code-signed.** Windows SmartScreen will warn on first run
("Windows protected your PC" → *More info* → *Run anyway*), and some antivirus
engines flag PyInstaller binaries as a well-known false positive. Signing needs a
certificate issued by a commercial authority against a verified identity, which
this project does not have. A self-signed certificate would **not** help you —
SmartScreen trust is tied to the certificate's reputation, and a fresh
self-signed one has none, so the warning would remain. The honest alternatives:

- **Verify the file instead** — see *Verifying your download* below.
- **Run from source** (`macOS-Linux/`, which also works on Windows). Nothing is
  compiled or hidden; you can read every line before running it.
- **Build it yourself** with `build_unix.sh`, or `build.ps1` on Windows.

## Verifying your download

`SHA256SUMS.txt` lists the SHA-256 hash of every file in this folder. If the
hash of the file you received matches, the file is byte-for-byte what was
published and was not altered in transit. (This proves integrity, not that the
publisher is trustworthy — the source is included so you can judge that
yourself.)

**Windows (PowerShell)**

```powershell
Get-FileHash .\Windows\HybridIDS.exe -Algorithm SHA256
```

**macOS**

```bash
shasum -a 256 Windows/HybridIDS.exe
```

**Linux** — verifies every file at once:

```bash
sha256sum -c SHA256SUMS.txt
```

Compare the result against the matching line in `SHA256SUMS.txt`. If it differs,
do not run the file.

If your antivirus quarantines the `.exe`, uploading it to
[virustotal.com](https://www.virustotal.com/) usually shows a small number of
engines flagging it heuristically while the majority pass — the signature of a
packer false positive rather than actual malware.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Wireshark is required but was not found" | Install Wireshark, then re-run. |
| Window never appears (Windows) | WebView2 missing — it now falls back to your browser. Read `%LOCALAPPDATA%\HybridIDS\desktop_server.log`. |
| Dashboard is empty on first open | Expected — no alert database ships. Let a capture run, or use `--no-capture` to browse an empty one. |
| No traffic appears | Not elevated, or the wrong interface was auto-detected. |
| "Model Intelligence" charts are blank | The SHAP charts need a trained `rf_model.pkl` (bundled) and the LSTM ones need `lstm_model.pt` (bundled too), so this should not happen — `torch`/`shap`/`matplotlib` now ship inside the exe. If a panel still reports missing deps, send `%LOCALAPPDATA%\HybridIDS\desktop_server.log`. |
| Antivirus flags the exe | Unsigned PyInstaller binary — a known false positive. |
