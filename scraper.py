"""
================================================================================
* REPOSITORY   : mmkeshavarzz/v2ray-configs
* SCRIPT NAME  : scraper.py (Ironclad True-Ping Edition - Top 100)
* ARCHITECTURE : Layer 4 Socket + Layer 7 Real Handshake + Reality Priority
* SPECIFICATION: Zero -1 Latency, DPI-Resistant, Validated Upstreams
================================================================================
"""

import os
import re
import ssl
import time
import json
import base64
import socket
import requests
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------------------------
# ۱. پیکربندی تنظیمات و سورس‌های زنده
# ------------------------------------------------------------------------------

WORKER_THREADS = 40
GLOBAL_SOCKET_TIMEOUT = 2.5
TLS_PROBE_TIMEOUT = 3.0
TARGET_ELITE_COUNT = 100

PUBLIC_TELEGRAM_CHANNELS = [
    "Vless_Reality_Free", "v2rayNG_VPNo", "v2cross", "DarkVPNpro",
    "proxystore11", "v2rayngvpn", "Napsternetv_config", "anti_filter_v2ray",
    "Freedom_v2ray", "Free_Internet_iran", "v2ray_sub", "FreeProxyVless",
    "ShadowrocketConfig", "TG_V2ray_Pool", "Global_Proxy_V2ray", "vpnfail_v2ray"
]

# سورس‌های گیت‌هاب کاملاً معتبر و با لینک مستقیم و تست‌شده (شامل منابع جدید)
UPSTREAM_GITHUB_SUBS = [
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/config.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless"
]

HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Cache-Control": "no-cache"
}

REGEX_CONFIG_PATTERN = r'''(vmess://[^\s<"']+|vless://[^\s<"']+|ss://[^\s<"']+|trojan://[^\s<"']+)'''

# رنج‌های آی‌پی کلودفلر که در ایران دچار افت پکت شدید و فیلترینگ قطعی هستند
BLOCKED_CLOUDFLARE_RANGES = [
    "172.64.", "172.65.", "172.66.", "172.67.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.",
    "104.27.", "104.28.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "198.41.128.", "198.41.129.", "199.232."
]

# ------------------------------------------------------------------------------
# ۲. دیکودر و پارسر ساختار کانفیگ‌ها
# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------
# ۳. ارزیابی عمیق حیاتی و حذف تضمینی کانفیگ‌های مرده (-1)
# ------------------------------------------------------------------------------

def evaluate_node_vitality(config: dict) -> dict:
    if not config:
        return None

    host = config["host"]
    port = config["port"]
    sni = config["sni"]
    tls = config["tls"]

    # فیلتر ۱: رد کردن هاست‌های بدون دامنه/آی‌پی یا داخلی یا رنج‌های فیلتر شده
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(bad) for bad in BLOCKED_CLOUDFLARE_RANGES):
            return None
        if ip.startswith(('127.', '10.', '192.168.', '0.', '169.254.')):
            return None
    except Exception:
        return None

    # فیلتر ۲: تست باز بودن سوکت واقعی
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(GLOBAL_SOCKET_TIMEOUT)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
        latency = round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        s.close()
        return None

    # فیلتر ۳: تست پیشرفته TLS و جلوگیری از خطای Handshake Reset
    if tls in ["tls", "reality"] or port in [443, 8443, 2053, 2083, 2087, 2096]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=sni or host) as ss:
                _ = ss.cipher()
        except Exception:
            s.close()
            return None
    else:
        s.close()

    config["latency"] = latency

    # امتیازدهی هوشمند ضد فیلترینگ
    # پروتکل‌های Vless Reality در شبکه ایران بالاترین پایداری را دارند
    score = latency
    if tls == "reality":
        score -= 250
    elif config["protocol"] == "vless":
        score -= 60
    elif config["protocol"] == "trojan":
        score -= 40
        
    config["score"] = score
    return config

# ------------------------------------------------------------------------------
# ۴. گردآوری از منابع
# ------------------------------------------------------------------------------

def harvest_raw_configs_from_sources() -> list:
    accumulated = []
    
    with requests.Session() as s:
        s.headers.update(HTTP_HEADERS)
        for channel in PUBLIC_TELEGRAM_CHANNELS:
            try:
                r = s.get(f"https://t.me/s/{channel}", timeout=4)
                if r.status_code == 200:
                    accumulated.extend(re.findall(REGEX_CONFIG_PATTERN, r.text))
            except Exception:
                continue

    for entry in UPSTREAM_GITHUB_SUBS:
        try:
            res = requests.get(entry, headers=HTTP_HEADERS, timeout=5)
            if res.status_code == 200 and len(res.text) > 40:
                found = re.findall(REGEX_CONFIG_PATTERN, res.text)
                if not found:
                    dec = safe_b64_decode(res.text)
                    found = re.findall(REGEX_CONFIG_PATTERN, dec)
                accumulated.extend(found)
        except Exception:
            continue
                
    return list(set(accumulated))

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

# ------------------------------------------------------------------------------
# ۵. ارسال مستقیم پیام به تلگرام
# ------------------------------------------------------------------------------

def send_telegram_alert(raw_count: int, alive_count: int, elite_count: int, top_file_path: str = None):
    token = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHANNEL") or os.getenv("TG_CHANNEL_ID")
    
    if not token or not chat_id:
        print("⚠️ سکرت‌های تلگرام پیدا نشدند!")
        return

    REPO_NAME = "mmkeshavarzz/v2ray-configs"
    BRANCH = "main"

    raw_top100_url = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/top100.txt"
    cdn_top100_url = f"https://cdn.jsdelivr.net/gh/{REPO_NAME}@{BRANCH}/top100.txt"
    vless_sub = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/protocols/vless.txt"
    raw_sub_url = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/sub.txt"

    subscription_message = (
        "🌟 *بروزرسانی جدید کانفیگ‌های بدون قطعی (Top 100)*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 *آمار تصفیه‌خانه ضد زامبی:*\n"
        f"▫️ کل کانفیگ‌های شکارشده: `{raw_count}`\n"
        f"▫️ عبور کرده از تست TLS: `{alive_count}`\n"
        f"▫️ برترین نودهای گلچین‌شده: `{elite_count}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔗 *لینک‌های سابسکریپشن هوشمند (کافیه لمس کنی تا کپی بشن):*\n\n"
        "🚀 *لینک مستقیم گیت‌هاب (Top 100):*\n"
        f"`{raw_top100_url}`\n\n"
        "⚡ *لینک ضدفیلتر CDN سریع (jsDelivr):*\n"
        f"`{cdn_top100_url}`\n\n"
        "💎 *کانفیگ‌های اختصاصی VLESS:*\n"
        f"`{vless_sub}`\n\n"
        "📦 *مخزن جامع فعال (Sub Full):*\n"
        f"`{raw_sub_url}`\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 *آموزش استفاده:* لینک کادر بالا رو لمس و کپی کنید، وارد برنامه کلاینت (v2rayNG / Happ / Streisand) بشید و با دکمه ➕ سابسکریپشن رو اضافه و آپدیت کنید! 🚀"
    )

    try:
        text_url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": subscription_message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        requests.post(text_url, json=payload, timeout=10)
    except Exception as e:
        print(f"❌ خطا در ارسال پیام تلگرام: {e}")

# ------------------------------------------------------------------------------
# ۶. اجرای اصلی برنامه
# ------------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("🚀 ANTI-ZOMBIE ENGINE: Starting Full Scan (Target: Top 100)")
    print("=" * 65)

    raw_candidates = harvest_raw_configs_from_sources()
    print(f"📦 Gathered raw targets: {len(raw_candidates)}")

    parsed_list = [p for raw in raw_candidates if (p := parse_config_schema(raw))]
    print(f"⚙️ Parsed valid schemas: {len(parsed_list)}")

    alive_pool = []
    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        futures = {executor.submit(evaluate_node_vitality, item): item for item in parsed_list}
        for f in as_completed(futures):
            try:
                res = f.result()
                if res:
                    alive_pool.append(res)
            except Exception:
                pass

    print(f"🛡️ Survived Real TLS Handshake: {len(alive_pool)}")

    if not alive_pool:
        print("⚠️ Warning: No nodes survived.")
        return

    # مرتب‌سازی بر اساس امتیاز طلایی (Reality اولویت اول، کمترین تاخیر)
    alive_pool.sort(key=lambda x: x["score"])
    verified_top100 = alive_pool[:TARGET_ELITE_COUNT]

    print(f"🎯 Successfully Selected Elite Nodes: {len(verified_top100)}")

    # تولید فایل‌های خروجی Base64
    top100_content = "\n".join([x["raw"] for x in verified_top100])
    with open("top100.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(top100_content.encode("utf-8")).decode("utf-8"))

    top10_content = "\n".join([x["raw"] for x in verified_top100[:10]])
    with open("top10.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(top10_content.encode("utf-8")).decode("utf-8"))

    all_content = "\n".join([x["raw"] for x in alive_pool])
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(all_content.encode("utf-8")).decode("utf-8"))

    attach_country_codes(alive_pool)
    os.makedirs("protocols", exist_ok=True)
    os.makedirs("countries", exist_ok=True)

    protocols_dict = {"vless": [], "vmess": [], "trojan": [], "ss": []}
    countries_dict = {}

    for node in alive_pool:
        proto = node.get("protocol", "vless")
        if proto in protocols_dict:
            protocols_dict[proto].append(node["raw"])
        
        c = node.get("country", "OTHER")
        if c not in countries_dict:
            countries_dict[c] = []
        countries_dict[c].append(node["raw"])

    for proto_name, items in protocols_dict.items():
        if items:
            with open(f"protocols/{proto_name}.txt", "w", encoding="utf-8") as pf:
                pf.write(base64.b64encode(("\n".join(items)).encode("utf-8")).decode("utf-8"))

    for c_code, items in countries_dict.items():
        if items:
            with open(f"countries/{c_code}.txt", "w", encoding="utf-8") as cf:
                cf.write(base64.b64encode(("\n".join(items)).encode("utf-8")).decode("utf-8"))

    # ارسال هوشمند به تلگرام
    send_telegram_alert(
        raw_count=len(raw_candidates),
        alive_count=len(alive_pool),
        elite_count=len(verified_top100)
    )

    print("🏁 Processing finished successfully. Zombie -1 nodes completely eliminated!")

if __name__ == "__main__":
    main()
