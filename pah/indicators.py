"""Indicators shared by the scanner and the guard's light paths (file reads, fetches).

Kept free of heavy imports so a hook that only needs to check a path or a URL starts fast.
"""
from __future__ import annotations

import re

SECRET_PATHS = re.compile(
    r"\.ssh[\\/](?:id_[a-z0-9_]+|authorized_keys|config)\b|\bid_(?:rsa|ed25519|ecdsa)\b"
    r"|\.aws[\\/](?:credentials|config)\b|\.config[\\/]gcloud\b|application_default_credentials\.json"
    r"|\.azure[\\/](?:accessTokens|msal_token_cache|azureProfile)|\.kube[\\/]config\b|\.docker[\\/]config\.json"
    r"|\.git-credentials\b|\.netrc\b|\.config[\\/]gh[\\/]hosts\.yml|\.pypirc\b"
    r"|\.claude[\\/]\.credentials\.json|\.claude\.json\b|\.codex[\\/]auth\.json|\.gemini[\\/](?:\.env|oauth_creds\.json)"
    r"|openclaw\.json\b|\.openclaw[\\/](?:credentials|device|openclaw)|\.cline[\\/]data[\\/]secrets\.json"
    r"|\.continue[\\/]config\.(?:ya?ml|json)|\bstate\.vscdb\b|\.copilot[\\/]hosts\.json|github-copilot[\\/](?:hosts|apps)\.json"
    r"|(?:Chrome|Chromium|Edge|Brave|Opera|Vivaldi|Yandex)[^\n]{0,80}(?:Login Data|Cookies|Local State|Web Data)"
    r"|\bLogin Data\b|\bkey[34]\.db\b|\blogins\.json\b|\bwallet\.dat\b|[\\/]Exodus[\\/]|[\\/]Electrum[\\/]"
    r"|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|login\.keychain|Library[\\/]Keychains",
    re.I)

EXFIL_HOSTS = re.compile(
    r"(?<![\w.-])(?:[\w-]+\.)*(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|oast\.(?:fun|pro|live|site|online|me)"
    r"|interact\.sh|burpcollaborator\.net|oastify\.com|ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|"
    r"pastebin\.com|transfer\.sh|file\.io|0x0\.st|temp\.sh|duckdns\.org|ddns\.net|no-ip\.(?:org|com|biz)|serveo\.net|"
    r"loca\.lt|beeceptor\.com|hookbin\.com|requestcatcher\.com|ipinfo\.io|ipify\.org|ifconfig\.me)(?![\w-])"
    r"|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot", re.I)

RAW_IP_URL = re.compile(r"\b(?:https?|tcp|udp)://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?", re.I)


def is_private_ip(ip: str) -> bool:
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return False
    return a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254)
