import requests
from concurrent.futures import ThreadPoolExecutor
from transform import safe_b64_decode

# ==============================================================================
# 🛰️ لیست منابع طلایی و فوق‌العاده جامع (اولویت‌بندی شده از VIP تا کمکی)
# ==============================================================================
UPSTREAM_GITHUB_SUBS = [
    # 👑 --- اولویت اول: شاه‌رگ‌ها و منابع اصلی درخواستی (VIP Sources) ---
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/iampedii/whitedns-sub/main/base64.txt",
    "https://openproxylist.com/v2ray/rawlist/text",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/iampedii/whitedns-sub/main/cloudflare-base64.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix/sub.html",
    "https://raw.githubusercontent.com/ShadowException/VPN/main/configs/VPN-cat",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/v2FreeHub/v2hub-configs/main/Sub-AutoUpdate",
    "https://raw.githubusercontent.com/prominbro/sub/main/212.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/luxxuria/harvester/main/speed_tested.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",

    # 🛡️ --- اولویت دوم: منابع معتبر قدیمی برای پوشش حداکثری (Backup Nodes) ---
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

TARGET_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hy2://")

def fetch_single_sub(url: str) -> list[str]:
    """دریافت و استخراج رکوردهای کانفیگ از یک منبع اینترنتی"""
    configs = []
    headers = {
        "User-": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code != 200:
            return configs

        content = resp.text.strip()
        if not content:
            return configs

        if not any(proto in content[:150].lower() for proto in ["vless://", "vmess://", "trojan://", "ss://"]):
            decoded = safe_b64_decode(content)
            if any(proto in decoded[:150].lower() for proto in ["vless://", "vmess://", "trojan://", "ss://"]):
                content = decoded

        for line in content.splitlines():
            line = line.strip()
            if line.startswith(TARGET_PROTOCOLS):
                configs.append(line)

    except Exception:
        pass

    return configs

def harvest_raw_configs_from_sources() -> list[str]:
    """درو کردن همزمان تمام سورس‌ها با ThreadPoolExecutor بدون اتلاف وقت"""
    all_raw = []
    print(f"📡 Harvesting from {len(UPSTREAM_GITHUB_SUBS)} upstream providers...")
    
    with ThreadPoolExecutor(max_workers=25) as executor:
        results = executor.map(fetch_single_sub, UPSTREAM_GITHUB_SUBS)
        for res in results:
            all_raw.extend(res)

    seen = set()
    deduped = []
    for c in all_raw:
        core_part = c.split("#")[0].strip()
        if core_part and core_part not in seen:
            seen.add(core_part)
            deduped.append(c)

    print(f"✅ Total unique raw configs pulled: {len(deduped)}")
    return deduped
