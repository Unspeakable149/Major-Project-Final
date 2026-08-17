"""Severe-alert notifier.

Sends to SMTP / Discord / Slack. Throttled to 1 per (source IP, channel)
per hour. Reads notifier_config.json (gitignored); template is .example.
Missing config = notifier off, IDS keeps running.
"""

import json
import os
import smtplib
import time
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CONFIG_FILE = "notifier_config.json"
THROTTLE_SECONDS = 3600  # one alert per (IP, channel) per hour

# {(src_ip, channel): last_sent_epoch}
_throttle_state: dict[tuple[str, str], float] = {}
_config_cache: dict | None = None
_config_loaded = False


def load_config() -> dict:
    global _config_cache, _config_loaded
    if _config_loaded:
        return _config_cache or {}

    _config_loaded = True
    if not os.path.exists(CONFIG_FILE):
        _config_cache = {}
        return _config_cache

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            _config_cache = json.load(f)
        enabled = [c for c in ("email", "discord", "slack")
                   if _config_cache.get(c, {}).get("enabled")]
        if enabled:
            print(f"[+] Notifier loaded. Active channels: {', '.join(enabled)}")
        else:
            print("[*] Notifier config present but no channels enabled.")
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] notifier: failed to load {CONFIG_FILE}: {e}")
        _config_cache = {}

    return _config_cache


def _throttled(src_ip: str, channel: str) -> bool:
    now = time.time()
    last = _throttle_state.get((src_ip, channel), 0.0)
    if now - last < THROTTLE_SECONDS:
        return True
    _throttle_state[(src_ip, channel)] = now
    return False


def _format_message(alert: dict) -> tuple[str, str]:
    subject = f"[Hybrid IDS] Severe Threat from {alert['source_ip']}"
    body = (
        "Hybrid IDS Severe Alert\n"
        "=======================\n"
        f"Timestamp: {alert['timestamp']}\n"
        f"Source IP: {alert['source_ip']}\n"
        f"Profile: {alert['profile']}\n"
        f"Threat: {alert['threat']}\n"
        f"Packets/sec: {alert['pps']:.1f}\n"
        f"SYN/ACK Ratio: {alert['sar']:.2f}\n"
        f"Total Bytes: {alert['total_bytes']}\n"
        f"Confidence: {alert['confidence'] * 100:.1f}%\n"
    )
    return subject, body


def _send_email(cfg: dict, subject: str, body: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"] = cfg["from_addr"]
        msg["To"] = ", ".join(cfg["to_addrs"])
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        host = cfg["smtp_host"]
        port = int(cfg.get("smtp_port", 587))
        use_ssl = bool(cfg.get("use_ssl", False))
        use_tls = bool(cfg.get("use_tls", True))

        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
        try:
            if use_tls and not use_ssl:
                server.starttls()
            if cfg.get("username"):
                server.login(cfg["username"], cfg["password"])
            server.send_message(msg)
        finally:
            server.quit()
        return True
    except Exception as e:
        print(f"[!] notifier: email send failed: {e}")
        return False


def _post_webhook(url: str, payload: dict) -> bool:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "HybridIDS/1.0 (Severe-Alert Notifier)",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        print(f"[!] notifier: webhook HTTP {e.code}: {e.reason}")
        return False
    except Exception as e:
        print(f"[!] notifier: webhook send failed: {e}")
        return False


def _send_discord(cfg: dict, subject: str, body: str) -> bool:
    payload = {
        "username": "Hybrid IDS",
        "embeds": [{
            "title": subject,
            "description": f"```\n{body}\n```",
            "color": 0xFF3333,
        }],
    }
    return _post_webhook(cfg["webhook_url"], payload)


def _send_slack(cfg: dict, subject: str, body: str) -> bool:
    payload = {"text": f"*{subject}*\n```\n{body}\n```"}
    return _post_webhook(cfg["webhook_url"], payload)


def notify_severe(alert: dict) -> None:
    """Fire-and-forget Severe notification.

    Expected keys: timestamp, source_ip, profile, threat, pps, sar,
    total_bytes, confidence. Exceptions are caught and logged so a
    broken notifier cannot crash the capture loop.
    """
    try:
        cfg = load_config()
        if not cfg:
            return

        src_ip = alert["source_ip"]
        subject, body = _format_message(alert)

        email_cfg = cfg.get("email", {})
        if email_cfg.get("enabled") and not _throttled(src_ip, "email"):
            _send_email(email_cfg, subject, body)

        discord_cfg = cfg.get("discord", {})
        if discord_cfg.get("enabled") and not _throttled(src_ip, "discord"):
            _send_discord(discord_cfg, subject, body)

        slack_cfg = cfg.get("slack", {})
        if slack_cfg.get("enabled") and not _throttled(src_ip, "slack"):
            _send_slack(slack_cfg, subject, body)
    except Exception as e:
        print(f"[!] notifier: unexpected error: {e}")
