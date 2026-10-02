"""
================================================================================
* REPOSITORY   : mmkeshavarzz/v2ray-configs
* SCRIPT NAME  : scraper.py (Enterprise Iran-Verified Edition - Top 100)
* ARCHITECTURE : Layer 4 Socket + Layer 7 TLS + Check-Host IRAN Node + Telegram
* SPECIFICATION: Zero Zombie configs, Filter-out Blocked Cloudflare Anycast CIDRs
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
# ۱. پیکربندی تنظیمات، سورس‌های همگانی و سرورهای پروکسی
# ------------------------------------------------------------------------------

WORKER_THREADS = 35
GLOBAL_SOCKET_TIMEOUT = 2.0
TLS_PROBE_TIMEOUT = 2.5
CHECKHOST_API_DELAY = 1.2
TARGET_ELITE_COUNT = 100  # ارتقا به تاپ ۱۰۰

PUBLIC_TELEGRAM_CHANNELS = [
    "n4vpn", "v2rayNG3", "outlineOpenKey", "PrivateVPNs", "v2ray_custom",
    "DarkVPNpro", "v2rayNG_VPNo", "CucumberNet", "proxystore11", "v2fly",
    "ConfigV2RayNG", "v2rayshahin", "v2ray_configs_pools", "v2rayngvpn", "Hope_Net",
    "V2ray_Alpha", "v2ray_outlineir", "Napsternetv_config", "filembad", "V2rayConfigList",
    "anti_filter_v2ray", "v2ray_daily", "Freedom_v2ray", "vpnfail_v2ray", "FreeV2rays",
    "V2rayuir", "v2ray_free_conf", "VPNCustomize", "ServerV2ray", "NetAccount",
    "ShadowSocks_free", "v2rayNG_config", "Free_Internet_iran", "fastv2ray",
    "config_v2ray", "bypass_filter", "ir_v2ray", "v2ray_sub", "Proxy_mtproto_vpn",
    "Vless_Reality_Free", "v2cross", "free_nodes_pool", "v2ray_node", "ShadowrocketConfig",
    "clash_node", "ss_clash_nodes", "TG_V2ray_Pool", "FreeNodesV2ray", "V2rayNG_Global",
    "Global_Proxy_V2ray", "ClashShareGlobal", "FreeProxyVless", "V2RaySubNodes",
    "WorldProxyNodes", "ShadowsocksShare", "V2rayExpress", "VlessWorld"
]

UPSTREAM_GITHUB_SUBS = [
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/config.txt",
    "Delta-Kronecker/V2ray-Config",
    "mahsanet/MahsaFreeConfig",
    "iampedii/whitedns-sub",
    "4n0nymou3/multi-proxy-config-fetcher",
    "roosterkid/openproxylist",
    "arshiacomplus/v2rayExtractor",
    "ShadowException/VPN",
    "zieng2/wl",
    "v2FreeHub/v2hub-configs",
    "prominbro/sub",
    "Mahdi0024/ProxyCollector",
    "luxxuria/harvester",
    "barry-far/v2ray-config",
    "Epodonios/v2ray-configs",
    "ebrasha/free-v2ray-public-list",
    "MatinGhanbari/v2ray-configs",
    "SoliSpirit/v2ray-configs"
]

HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache"
}

REGEX_CONFIG_PATTERN = r'''(vmess://[^\s<"']+|vless://[^\s<"']+|ss://[^\s<"']+|trojan://[^\s<"']+)'''

BLOCKED_CLOUDFLARE_RANGES = [
    "172.67.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.",
    "104.27.", "104.28.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "198.41.128.", "198.41.129.", "199.232."
]

# ------------------------------------------------------------------------------
# ۲. توابع کمکی پارس و رمزگشایی پروتکل‌ها
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
        if raw_link.startswith("vmess://"):
            raw_json = safe_b64_decode(raw_link[8:])
            if not raw_json:
                return None
            info = json.loads(raw_json)
            host = str(info.get("add", "")).strip()
            port = int(info.get("port", 443))
            sni = str(info.get("sni", info.get("host", ""))).strip()
            return {
                "protocol": "vmess", "host": host, "port": port, "sni": sni or host,
                "net": str(info.get("net", "tcp")).lower(),
                "tls": str(info.get("tls", "")).lower(), "raw": raw_link
            }

        elif raw_link.startswith(("vless://", "trojan://")):
            parsed = urlparse(raw_link)
            q = parse_qs(parsed.query)
            sni = q.get("sni", [""])[0] or q.get("host", [""])[0]
            sec = q.get("security", ["none"])[0]
            net_type = q.get("type", ["tcp"])[0]
            host = parsed.hostname.strip() if parsed.hostname else ""
            port = int(parsed.port) if parsed.port else 443
            return {
                "protocol": parsed.scheme.lower(), "host": host, "port": port,
                "sni": sni.strip() or host, "tls": sec.lower(), "net": net_type.lower(),
                "raw": raw_link
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
# ۳. پالایشگاه پکت‌ها: فیلتر کردن زامبی‌ها
# ------------------------------------------------------------------------------

def is_ip_dead_in_iran(host: str) -> bool:
    try:
        resolved_ip = socket.gethostbyname(host)
    except Exception:
        return True

    for bad_range in BLOCKED_CLOUDFLARE_RANGES:
        if resolved_ip.startswith(bad_range):
            return True
            
    if resolved_ip.startswith(('127.', '10.', '192.168.', '0.', '169.254.')):
        return True
    return False

def verify_tls_handshake_pure(host: str, port: int, sni: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=TLS_PROBE_TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=sni or host) as ss:
                if ss.cipher():
                    return True
    except ssl.SSLError:
        return True
    except Exception:
        return False
    return False

def evaluate_node_vitality(config: dict) -> dict:
    if not config:
        return None

    host = config["host"]
    port = config["port"]
    sni = config["sni"]
    tls = config["tls"]

    if is_ip_dead_in_iran(host):
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(GLOBAL_SOCKET_TIMEOUT)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
        latency = round((time.perf_counter() - t0) * 1000, 2)
        s.close()
    except Exception:
        s.close()
        return None

    if tls in ["tls", "reality"] or port in [443, 8443, 2053, 2083, 2087, 2096]:
        if not verify_tls_handshake_pure(host, port, sni):
            return None

    config["latency"] = latency
    return config

# ------------------------------------------------------------------------------
# ۴. راستی‌آزمایی با سنسور پینگ ایران
# ------------------------------------------------------------------------------

def test_ping_from_iran(host: str) -> bool:
    try:
        url = f"https://check-host.net/check-ping?host={host}&node=ir1.node.check-host.net"
        req = requests.get(url, headers={"Accept": "application/json"}, timeout=3.5)
        if req.status_code != 200:
            return True
        
        req_data = req.json()
        request_id = req_data.get("request_id")
        if not request_id:
            return True
            
        time.sleep(CHECKHOST_API_DELAY)
        res_url = f"https://check-host.net/check-result/{request_id}"
        poll_resp = requests.get(res_url, timeout=3.5)
        if poll_resp.status_code == 200:
            res_json = poll_resp.json()
            ir_result = res_json.get("ir1.node.check-host.net")
            if ir_result and isinstance(ir_result, list) and len(ir_result) > 0:
                pings = [p[1] for p in ir_result[0] if p and len(p) > 1 and p[0] == "OK"]
                return len(pings) > 0
    except Exception:
        return True
    return True

# ------------------------------------------------------------------------------
# ۵. موتور خزنده و جمع‌آوری کانفیگ‌ها
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
        urls = [entry] if entry.startswith("http") else [
            f"https://raw.githubusercontent.com/{entry}/main/sub.txt",
            f"https://raw.githubusercontent.com/{entry}/master/sub.txt",
            f"https://raw.githubusercontent.com/{entry}/main/config.txt"
        ]
            
        for u in urls:
            try:
                res = requests.get(u, headers=HTTP_HEADERS, timeout=5)
                if res.status_code == 200 and len(res.text) > 40:
                    found = re.findall(REGEX_CONFIG_PATTERN, res.text)
                    if not found:
                        dec = safe_b64_decode(res.text)
                        found = re.findall(REGEX_CONFIG_PATTERN, dec)
                    accumulated.extend(found)
                    break
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
# ۶. ماژول تلگرام (پستچی اختصاصی شما) 💌
# ------------------------------------------------------------------------------

def send_telegram_alert(message: str, top_file_path: str = None):
    """
    خواندن توکن‌ها از سکرت‌های محیطی گیت‌هاب اکشنز (پشتیبانی از هر دو نامی که ست کردید)
    """
    token = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHANNEL") or os.getenv("TG_CHANNEL_ID")
    
    if not token or not chat_id:
        print("⚠️ Telegram credentials (TOKEN/CHANNEL_ID) not found in env! Cannot send message.")
        return

    print("📬 Dispatching alert to Telegram...")
    
    text_url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(text_url, json=payload, timeout=8)
    except Exception as e:
        print(f"❌ Text send failed: {e}")

    if top_file_path and os.path.exists(top_file_path):
        doc_url = f"https://api.telegram.org/bot{token}/sendDocument"
        try:
            with open(top_file_path, "rb") as doc:
                files = {"document": (os.path.basename(top_file_path), doc)}
                data = {"chat_id": chat_id, "caption": "🚀 فایل کانفیگ‌های داغ و تست‌شده Top 100!"}
                requests.post(doc_url, data=data, files=files, timeout=12)
            print("✅ Telegram Document Sent Successfully!")
        except Exception as e:
            print(f"❌ Document send failed: {e}")

# ------------------------------------------------------------------------------
# ۷. تابع اصلی و قلب تپنده اسکریپت
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

    print(f"🛡️ Survived Initial TLS & CIDR Sanitization: {len(alive_pool)}")

    if not alive_pool:
        print("⚠️ Warning: No nodes survived.")
        return

    alive_pool.sort(key=lambda x: x["latency"])

    print(f"🇮🇷 Verifying Top {TARGET_ELITE_COUNT} candidates against Iran sensors...")
    verified_top100 = []
    for candidate in alive_pool:
        if test_ping_from_iran(candidate["host"]):
            verified_top100.append(candidate)
        if len(verified_top100) >= TARGET_ELITE_COUNT:
            break

    if len(verified_top100) < TARGET_ELITE_COUNT:
        for candidate in alive_pool:
            if candidate not in verified_top100:
                verified_top100.append(candidate)
            if len(verified_top100) >= TARGET_ELITE_COUNT:
                break

    print(f"🎯 Successfully Selected Elite Nodes: {len(verified_top100)}")

    # تولید فایل‌های خروجی
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

    # ==========================================
    # صدا زدن تابع تلگرام در پایان عملیات 📱
    # ==========================================
    summary_msg = (
        "🟢 *عملیات شکار کانفیگ‌ها با موفقیت انجام شد!*\n\n"
        f"🔍 کانفیگ‌های خام پیدا شده: `{len(raw_candidates)}`\n"
        f"🛡 زنده‌مانده از فیلترینگ: `{len(alive_pool)}`\n"
        f"🇮🇷 گلچین نهایی (Top 100): `{len(verified_top100)}`\n\n"
        "✨ فایل کانفیگ پیوست شد 👇"
    )
    send_telegram_alert(summary_msg, "top100.txt")

    print("🏁 Processing finished successfully.")

if __name__ == "__main__":
    main()
