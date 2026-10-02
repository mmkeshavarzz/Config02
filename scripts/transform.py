import json
import base64
import random
import re
from urllib.parse import quote
import requests

def safe_b64_decode(data_str: str) -> str:
    if not data_str:
        return ""
    clean_str = data_str.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    pad = len(clean_str) % 4
    if pad:
        clean_str += "=" * (4 - pad)
    try:
        return base64.b64decode(clean_str).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def country_code_to_emoji(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🌐"
    code = country_code.upper()
    try:
        return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))
    except Exception:
        return "🌐"

def generate_hex_id(length: int = 6) -> str:
    chars = "0123456789ABCDEF"
    return "".join(random.choice(chars) for _ in range(length))

def rebrand_config(raw_link: str, country_code: str) -> str:
    try:
        raw_link = raw_link.strip()
        if not raw_link:
            return ""

        c_code = country_code.upper() if (country_code and len(country_code) == 2) else "XX"
        flag = country_code_to_emoji(c_code)
        hex_id = generate_hex_id(6)
        
        custom_name = f"{flag} {c_code} | @mmkeshavarz | {hex_id}"

        if raw_link.startswith("vmess://"):
            raw_b64 = raw_link[8:]
            decoded_json = safe_b64_decode(raw_b64)
            if not decoded_json:
                return raw_link
            data = json.loads(decoded_json)
            data["ps"] = custom_name
            encoded_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
            return "vmess://" + base64.b64encode(encoded_bytes).decode("utf-8")

        elif any(raw_link.startswith(p) for p in ["vless://", "trojan://", "ss://", "hysteria://", "hy2://"]):
            base_part = raw_link.split("#")[0]
            encoded_title = quote(custom_name)
            return f"{base_part}#{encoded_title}"

        return raw_link
    except Exception:
        return raw_link

def parse_config_schema(raw_link: str) -> dict:
    if not raw_link or not isinstance(raw_link, str):
        return None

    raw_link = raw_link.strip()
    try:
        clean_target = raw_link.split("#")[0]

        if clean_target.startswith(("vless://", "trojan://")):
            pattern = r"://(?:[^@]+@)?(\[[a-fA-F0-9:]+\]|[^/:]+)(?::(\d+))?"
            match = re.search(pattern, clean_target)
            if not match:
                return None

            host = match.group(1).strip("[]")
            port = int(match.group(2)) if match.group(2) else 443

            tls = "none"
            if "security=reality" in clean_target:
                tls = "reality"
            elif "security=tls" in clean_target or "tls" in clean_target:
                tls = "tls"

            sni_match = re.search(r"[?&]sni=([^&]+)", clean_target)
            sni = sni_match.group(1) if sni_match else host

            net_match = re.search(r"[?&]type=([^&]+)", clean_target)
            net_type = net_match.group(1).lower() if net_match else "tcp"

            proto = "vless" if clean_target.startswith("vless://") else "trojan"

            return {
                "protocol": proto, "host": host, "port": port,
                "sni": sni, "tls": tls, "net": net_type, "raw": raw_link
            }

        elif clean_target.startswith("vmess://"):
            raw_b64 = clean_target[8:]
            decoded_json = safe_b64_decode(raw_b64)
            if not decoded_json:
                return None
            info = json.loads(decoded_json)
            host = str(info.get("add", "")).strip()
            port = int(info.get("port", 443))
            sni = str(info.get("sni", info.get("host", host))).strip()

            return {
                "protocol": "vmess", "host": host, "port": port,
                "sni": sni, "tls": str(info.get("tls", "none")).lower(),
                "net": str(info.get("net", "tcp")).lower(), "raw": raw_link
            }

        elif clean_target.startswith("ss://"):
            pattern = r"@(\[[a-fA-F0-9:]+\]|[^/:]+):(\d+)"
            match = re.search(pattern, clean_target)
            if match:
                host = match.group(1).strip("[]")
                port = int(match.group(2))
                return {
                    "protocol": "ss", "host": host, "port": port,
                    "sni": "", "tls": "none", "net": "tcp", "raw": raw_link
                }
    except Exception:
        return None

    return None

def attach_country_codes(nodes: list):
    if not nodes:
        return

    unique_hosts = list({node["host"] for node in nodes if node.get("host")})
    host_to_country = {}

    for i in range(0, len(unique_hosts), 100):
        batch = unique_hosts[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=batch, timeout=5)
            if r.status_code == 200:
                for row in r.json():
                    if row.get("status") == "success":
                        host_to_country[row.get("query")] = row.get("countryCode", "US")
        except Exception:
            pass

    for node in nodes:
        c_code = host_to_country.get(node.get("host"), "US")
        node["country"] = c_code
        # ‼️ این خطه که اونجادوی اسم رو میزنه:
        node["raw"] = rebrand_config(node.get("raw", ""), c_code)
