import json
import base64
import random
from urllib.parse import urlparse, parse_qs, quote, unquote
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

def country_code_to_emoji(country_code: str) -> str:
    """تبدیل کد دو حرفی کشور به ایموجی پرچم واقعی (مثلا DE -> 🇩🇪)"""
    if not country_code or len(country_code) != 2:
        return "🌐"
    code = country_code.upper()
    try:
        # کد اسکی پرچم‌ها در استاندارد یونیکد
        return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))
    except Exception:
        return "🌐"

def rebrand_config(raw_link: str, country_code: str) -> str:
    """تغییر نام کانفیگ به فرمت: [پرچم] | @mmkeshavarz | [کد ۶ رقمی]"""
    flag = country_code_to_emoji(country_code)
    rand_code = random.randint(100000, 999999)
    custom_name = f"{flag} | @mmkeshavarz | {rand_code}"
    
    raw_link = raw_link.strip()

    try:
        # هندل کردن VMess که نام داخل فرمت json درون Base64 قرار دارد
        if raw_link.startswith("vmess://"):
            raw_b64 = raw_link[8:]
            decoded_json = safe_b64_decode(raw_b64)
            if not decoded_json:
                return raw_link
            data = json.loads(decoded_json)
            data["ps"] = custom_name  # کلید ps همان نام کانفیگ است
            new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"

        # هندل کردن VLESS, Trojan, Shadowsocks که نام در انتهای لینک پس از # قرار دارد
        elif raw_link.startswith(("vless://", "trojan://", "ss://")):
            base_part = raw_link.split("#")[0]
            encoded_name = quote(custom_name)
            return f"{base_part}#{encoded_name}"

    except Exception:
        return raw_link

    return raw_link

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
        c_code = host_to_country.get(node["host"], "OTHER")
        node["country"] = c_code
        # اعمال فوری نام‌گذاری برند شده روی لینک خام کانفیگ
        node["raw"] = rebrand_config(node["raw"], c_code)
