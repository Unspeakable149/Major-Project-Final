# Security notice

Read this before running Hybrid IDS on anything that matters. These are
properties of how the system works, not bugs waiting to be fixed.

---

## Only run this on a network you are authorised to monitor

It captures and inspects live packet traffic. Doing that on a network you do not
own, or do not have written permission to test, may be illegal where you live —
regardless of intent. This is an academic project; treat it as one.

---

## It runs elevated

Administrator on Windows, root on macOS and Linux. Packet capture and firewall
modification both require it, and there is no reduced-privilege mode that keeps
live capture working.

To avoid running the whole app as root on Linux, grant only the capture helper
the capability it needs:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(which dumpcap)"
```

To browse saved results with no elevation at all, use `--no-capture`.

---

## There is no authentication

The dashboard has no login screen. It binds to `127.0.0.1` only, and **that
loopback binding is the only thing keeping it private.** Anyone who can reach the
port gets full control, including the ability to add firewall rules.

Therefore:

- Do not change `server.address` in `Aalok/Dashboard/.streamlit/config.toml`
- Do not port-forward it, reverse-proxy it, or expose it through a tunnel
- Do not run it on a shared machine you do not trust

---

## The firewall buttons really change your firewall

"Block IP" installs a Windows Defender rule named `IDS_BLOCK_<ip>`. It persists
after the app closes. Remove rules from the dashboard, or manually:

```
netsh advfirewall firewall delete rule name=IDS_BLOCK_<ip>
```

Auto-blocking is **off by default**. When switched on it blocks a source after 3
Severe alerts, with a 1-hour TTL. A misconfigured baseline whitelist plus
auto-blocking can lock you out of your own gateway — whitelist your gateway and
DNS resolver before enabling it.

On macOS and Linux these buttons report as unsupported. They shell out to
Windows' `netsh`.

---

## Credentials are stored in clear text

`Aalok/Dashboard/notifier_config.json` holds the SMTP password and any webhook
URLs unencrypted. SMTP AUTH needs the original secret, so there is no way around
this.

- Use a throwaway or app-specific password, never a primary account password
- Never share or commit a filled-in copy — the file is gitignored, and only the
  `.example` template is published
- The same applies to `baseline.txt`, which contains real host and network
  addresses

---

## What this repository deliberately does not contain

Because these carry real data from a real network:

- **Alert databases** (`ids_logs.db`) — real classified traffic
- **Packet captures** (`*.pcap`) — real traffic, including credential material
- **Training datasets and model snapshots**
- **Filled-in `notifier_config.json` and `baseline.txt`**
- **PyInstaller build output**

One dataset is published, because reproducing the spec metrics depends on it:
`Aalok/Dashboard/ai_ready_advanced_flows.csv`. Its `Source IP` column is
pseudonymised — every routable address is replaced with `host_NNN`, while RFC1918
and CIC-IDS-2017 addresses are kept so the public dataset stays recognisable. The
column is an identifier and never a model input, so every published metric
reproduces exactly.

---

## Binary releases are unsigned

`HybridIDS.exe` is an unsigned PyInstaller binary. Antivirus products flag that
pattern routinely, and it is a false positive — but "it's a false positive" is
exactly what a malicious binary would also claim. Verify the SHA-256 published
with the release rather than taking it on trust, or build from source.

---

## Reporting a problem

This is a completed academic project and is not actively maintained. If you find
something genuinely dangerous, open an issue on the repository.
