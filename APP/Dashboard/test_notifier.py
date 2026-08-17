"""Notifier diagnostic + smoke test. Run from Dashboard/ directory."""

import json
import os

import notifier

print("=" * 60)
print("NOTIFIER DIAGNOSTICS")
print("=" * 60)

# 1. Working directory
print(f"\n[1] cwd: {os.getcwd()}")

# 2. Config file presence
cfg_path = "notifier_config.json"
exists = os.path.exists(cfg_path)
print(f"[2] {cfg_path} exists? {exists}")
if not exists:
    print("    -> Copy notifier_config.json.example to notifier_config.json first.")
    raise SystemExit(1)

# 3. Raw file content
print(f"\n[3] Raw config content:")
with open(cfg_path, "r", encoding="utf-8") as f:
    raw = f.read()
print(raw)

# 4. JSON parse
print("[4] JSON parse...")
try:
    parsed = json.loads(raw)
    print("    PARSED OK")
except json.JSONDecodeError as e:
    print(f"    PARSE FAILED: {e}")
    raise SystemExit(1)

# 5. Channel enable flags
print("\n[5] Channel status:")
for ch in ("email", "discord", "slack"):
    block = parsed.get(ch, {})
    en = block.get("enabled", False)
    marker = "ENABLED " if en else "disabled"
    print(f"    {ch:<8} : {marker}")
    if ch == "discord" and en:
        url = block.get("webhook_url", "")
        print(f"               webhook_url: {url[:50]}...")
        if not url.startswith("https://discord.com/api/webhooks/"):
            print("               WARNING: URL does not look like a Discord webhook URL")

# 6. Force-reload cache so changes since last run take effect
notifier._config_cache = None
notifier._config_loaded = False

print("\n[6] Calling notifier.load_config()...")
cfg = notifier.load_config()
print(f"    loaded keys: {list(cfg.keys())}")

# 7. Fire test alert with throttle disabled
print("\n[7] Firing test Severe alert (throttle bypassed)...")
notifier._throttle_state.clear()
notifier.THROTTLE_SECONDS = 0  # disable throttle for repeat tests

alert = {
    "timestamp": "12:00:00",
    "source_ip": "10.0.0.99",
    "profile": "Test DDoS SYN Flood",
    "threat": "Severe (Critical Anomaly)",
    "pps": 1234.5,
    "sar": 9.1,
    "total_bytes": 500000,
    "confidence": 0.95,
}
notifier.notify_severe(alert)

# 8. Direct webhook POST (bypass notifier wrapper) for Discord
discord_block = cfg.get("discord", {})
if discord_block.get("enabled"):
    print("\n[8] Direct Discord webhook POST (raw urllib)...")
    import urllib.request
    payload = json.dumps({"content": "Hybrid IDS direct webhook smoke test."}).encode("utf-8")
    req = urllib.request.Request(
        discord_block["webhook_url"],
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "HybridIDS/1.0 (Severe-Alert Notifier)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"    HTTP {resp.status} - webhook accepted")
    except Exception as e:
        print(f"    DIRECT POST FAILED: {e}")

print("\n" + "=" * 60)
print("DONE. Check your Discord channel.")
print("=" * 60)
