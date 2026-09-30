"""
=============================================================================
*  Project: Config Hunter & Auto Categorizer (Turbine Style) + Telegram Bot
*  Author: mm.keshavarz | Cleaned & Supercharged by Senior Dev
*  Features:
*    - Multi-threaded TCP Ping & Handshake latency tester
*    - Protocol separation (VLESS, VMess, Trojan, Shadowsocks)
*    - GeoIP lookup (Countries: DE, US, TR, NL, etc.)
*    - Clean folder structuring & Base64 encoding
*    - 🚀 Auto-Broadcast to Telegram with Fastly Sub Links!
=============================================================================
"""

import os
import re
import ssl
import json
import base64
import socket
import requests
import time
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================================================================
# 🛰️ لیست جامع و پالایش‌شده ۶۰ کانال تلگرامی
# ==============================================================================
CHANNELS = [
    # --- ۴۰ کانال داخلی ---
    "n4vpn", "v2rayNG3", "outlineOpenKey", "PrivateVPNs", "v2ray_custom",
    "DarkVPNpro", "v2rayNG_VPNo", "CucumberNet", "proxystore11", "v2fly",
    "ConfigV2RayNG", "v2rayshahin", "v2ray_configs_pools", "v2rayngvpn", "Hope_Net",
    "V2ray_Alpha", "v2ray_outlineir", "Napsternetv_config", "filembad", "V2rayConfigList",
    "anti_filter_v2ray", "v2ray_daily", "Freedom_v2ray", "vpnfail_v2ray", "FreeV2rays", 
    "V2rayuir", "v2ray_free_conf", "VPNCustomize", "ServerV2ray", "NetAccount", 
    "ShadowSocks_free", "v2rayNG_config", "Free_Internet_iran", "fastv2ray", 
    "config_v2ray", "bypass_filter", "ir_v2ray", "v2ray_sub", "Proxy_mtproto_vpn", 
    "Vless_Reality_Free",
    # --- ۲۰ کانال بین‌المللی ---
    "v2cross", "free_nodes_pool", "v2ray_node", "ShadowrocketConfig", "clash_node",
    "ss_clash_nodes", "TG_V2ray_Pool", "FreeNodesV2ray", "V2rayNG_Global",
    "Global_Proxy_V2ray", "ClashShareGlobal", "FreeProxyVless", "V2RaySubNodes",
    "WorldProxyNodes", "ShadowsocksShare", "V2rayExpress", "VlessWorld",
    "NodesShareInternational", "FreeV2rayNode", "NodeCollectorGlobal"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

REGEX_PATTERN = r'''(vmess://[^\s<"']+|vless://[^\s<"']+|ss://[^\s<"']+|trojan://[^\s<"']+)'''
MAX_TIMEOUT = 2.5
MAX_WORKERS = 40

# =============================================================================
#  پارس کانفیگ‌ها
# =============================================================================
def parse_config(config_str: str):
    try:
        if config_str.startswith("vmess://"):
            raw_b64 = config_str.replace("vmess://", "")
            missing_padding = len(raw_b64) % 4
            if missing_padding:
                raw_b64 += "=" * (4 - missing_padding)
            decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            return {"protocol": "vmess", "host": data.get("add", "").strip(), "port": int(data.get("port", 443)), "raw": config_str}
        
        elif config_str.startswith(("vless://", "trojan://")):
            parsed = urlparse(config_str)
            protocol = parsed.scheme.lower()
            host = parsed.hostname.strip() if parsed.hostname else ""
            port = parsed.port if parsed.port else 443
            return {"protocol": protocol, "host": host, "port": int(port), "raw": config_str}
            
        elif config_str.startswith("ss://"):
            parsed = urlparse(config_str)
            host = parsed.hostname.strip() if parsed.hostname else ""
            port = parsed.port if parsed.port else 443
            if not host and "@" in parsed.netloc:
                netloc_part = parsed.netloc.split("@")[-1]
                host, port_str = netloc_part.split(":")
                port = int(port_str.split("#")[0])
            return {"protocol": "ss", "host": host, "port": int(port), "raw": config_str}
    except Exception:
        pass
    return None

# =============================================================================
#  تست کانکشن
# =============================================================================
def check_alive_and_ping(config_data):
    if not config_data or not config_data.get("host") or not config_data.get("port"):
        return None
    host, port = config_data["host"], config_data["port"]
    if host in ["127.0.0.1", "localhost", "0.0.0.0"]:
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(MAX_TIMEOUT)
    start_time = time.time()
    try:
        sock.connect((host, port))
        latency = round((time.time() - start_time) * 1000, 2)
        sock.close()
        config_data["ping"] = latency
        return config_data
    except Exception:
        sock.close()
        return None

# =============================================================================
#  دریافت کشور
# =============================================================================
GEO_CACHE = {}
def get_country_code(host: str) -> str:
    if host in GEO_CACHE: return GEO_CACHE[host]
    try:
        ip_addr = socket.gethostbyname(host)
        res = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=countryCode,status", timeout=2)
        if res.status_code == 200 and res.json().get("status") == "success":
            country = res.json().get("countryCode", "OTHER").upper()
            GEO_CACHE[host] = country
            return country
    except Exception:
        pass
    GEO_CACHE[host] = "OTHER"
    return "OTHER"

# =============================================================================
# 🚀 ارسال به تلگرام (جدید)
# =============================================================================
def send_to_telegram(country_code, configs):
    bot_token = os.environ.get("TELEGRAM_TOKEN")
    channel_id = os.environ.get("TELEGRAM_CHANNEL")
    repo_name = os.environ.get("GITHUB_REPOSITORY") # فرمت: username/repo

    if not bot_token or not channel_id or not repo_name:
        print("⚠️ توکن تلگرام یا آیدی کانال تنظیم نشده است. پرش از ارسال تلگرام...")
        return

    # ساخت لینک ساب بر اساس ریپو
    sub_link = f"https://fastly.jsdelivr.net/gh/{repo_name}@main/countries/{country_code}.txt"
    
    # ساخت پیام با کلاس و خوشگل
    msg = f"🌍 **Country:** #{country_code}\n"
    msg += f"⚡ **Status:** Alive & Fast 🚀\n\n"
    msg += f"🔗 **Sub Link (Copy & Import):**\n`{sub_link}`\n\n"
    msg += f"🔥 **Top {len(configs)} Configs (By Ping):**\n"

    # اضافه کردن کانفیگ‌ها به پیام (مدیریت محدودیت ۴۰۹۶ کاراکتری تلگرام)
    configs_text = ""
    for cfg in configs:
        # اگر پیام خیلی طولانی شد، بقیه‌اش رو نذار که ارور نده
        if len(msg) + len(configs_text) + len(cfg) + 50 > 4000:
            configs_text += "\n... *(و موارد بیشتر در لینک ساب بالا)*"
            break
        configs_text += f"\n`{cfg}`\n"

    msg += configs_text

    # ارسال به API تلگرام
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": channel_id,
            "text": msg,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"❌ خطا در ارسال به تلگرام برای {country_code}: {e}")

# =============================================================================
#  موتور اصلی
# =============================================================================
def main():
    print("🕵️‍♂️ در حال نفوذ به کانال‌های تلگرامی برای استخراج کانفیگ...")
    raw_configs = []
    for ch in CHANNELS:
        try:
            res = requests.get(f"https://t.me/s/{ch}", headers=HEADERS, timeout=12)
            if res.status_code == 200:
                found = re.findall(REGEX_PATTERN, res.text)
                raw_configs.extend([c.strip() for c in found])
            time.sleep(0.5)
        except Exception:
            pass

    unique_raw = list(set(raw_configs))
    parsed_items = [parse_config(c) for c in unique_raw if parse_config(c)]
    
    alive_configs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_cfg = {executor.submit(check_alive_and_ping, cfg): cfg for cfg in parsed_items}
        for future in as_completed(future_to_cfg):
            res = future.result()
            if res: alive_configs.append(res)

    if not alive_configs: return

    alive_configs.sort(key=lambda x: x.get("ping", 9999))

    os.makedirs("protocols", exist_ok=True)
    os.makedirs("countries", exist_ok=True)

    protocol_buckets, country_buckets = {"vless": [], "vmess": [], "trojan": [], "ss": []}, {}

    for item in alive_configs:
        proto = item["protocol"]
        if proto in protocol_buckets:
            protocol_buckets[proto].append(item["raw"])
        cc = get_country_code(item["host"])
        if cc not in country_buckets: country_buckets[cc] = []
        country_buckets[cc].append(item["raw"])

    for proto, items in protocol_buckets.items():
        if items:
            with open(f"protocols/{proto}.txt", "w", encoding="utf-8") as f:
                f.write(base64.b64encode(("\n".join(items)).encode("utf-8")).decode("utf-8"))

    # ذخیره فایل کشورها + ارسال به تلگرام
    for cc, items in country_buckets.items():
        if items:
            with open(f"countries/{cc}.txt", "w", encoding="utf-8") as f:
                f.write(base64.b64encode(("\n".join(items)).encode("utf-8")).decode("utf-8"))
            # 🚀 ارسال مستقیم پکیج این کشور به کانال تلگرام
            send_to_telegram(cc, items)
            time.sleep(1) # یه نفس کوچیک بین ارسال پیام‌ها که تلگرام بن نکنه

    final_b64 = base64.b64encode(("\n".join([x["raw"] for x in alive_configs])).encode("utf-8")).decode("utf-8")
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(final_b64)
        
    print("🎉 عملیات با موفقیت به پایان رسید!")

if __name__ == "__main__":
    main()
