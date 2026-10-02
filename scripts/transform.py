import json
import base64
from urllib.parse import urlparse, parse_qs
import requests

def safe_b64_decode(data_str: str) -> str:
    clean_str = data_str.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    pad = len(clean_str) % 4
    if pad:
        clean_str += "=" * (4 - pad)
    try:
        return base64.b64decode(clean_str).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def parse_config_schema(raw_link: str) -> dict:
    raw_link = raw_link.strip()
    if not raw_link:
        return None

    try:
        if raw_link.startswith(("vless://", "trojan://")):
            parsed = urlparse(raw_link)
            q = parse_qs(parsed.query)
            sni = q.get("sni", [""])[0] or q.get("host", [""])[0]
            sec = q.get("security", ["none"])[0].lower()
            net_type = q.get("type", ["tcp"])[0].lower()
            host = parsed.hostname.strip() if parsed.hostname else ""
            port = int(parsed.port) if parsed.port else 443
            return {
                "protocol": parsed.scheme.lower(), "host": host, "port": port,
                "sni": sni.strip() or host, "tls": sec, "net": net_type,
                "raw": raw_link
            }

        elif raw_link.startswith("vmess://"):
            raw_json = safe_b64_decode(raw_link[8:])
            if not raw_json:
                return None
            info = json.loads(raw_json)
            host = str(info.get("add", "")).strip()
            port = int(info.get("port", 443))
            sni = str(info.get("sni", info.get("host", ""))).strip()
            return {
                "protocol": "vmess", "host": host, "port": port,
                "sni": sni or host, "tls": str(info.get("tls", "none")).lower(),
                "net": str(info.get("net", "tcp")).lower(), "raw": raw_link
            }

        elif raw_link.startswith("ss://"):
            parsed = urlparse(raw_link)
            host = parsed.hostname or ""
            port = parsed.port or 443
            if not host and "@" in parsed.netloc:
                back_part = parsed.netloc.split("@")[-1]
                host = back_part.split(":")[0]
                port = int(back_part.split(":")[1].split("#")[0])
            return {
                "protocol": "ss", "host": host.strip(), "port": int(port),
                "sni": "", "tls": "none", "net": "tcp", "raw": raw_link
            }
    except Exception:
        return None
    return None

def attach_country_codes(nodes: list):
    unique_hosts = list({node["host"] for node in nodes if node.get("host")})
    host_to_country = {}

    for i in range(0, len(unique_hosts), 100):
        batch = unique_hosts[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=batch, timeout=6)
            if r.status_code == 200:
                for row in r.json():
                    if row.get("status") == "success":
                        host_to_country[row.get("query")] = row.get("countryCode", "OTHER")
        except Exception:
            pass

    for node in nodes:
        node["country"] = host_to_country.get(node["host"], "OTHER")
