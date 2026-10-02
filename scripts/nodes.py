import re
import requests
from transform import safe_b64_decode

PUBLIC_TELEGRAM_CHANNELS = [
    "Vless_Reality_Free", "v2rayNG_VPNo", "v2cross", "DarkVPNpro",
    "proxystore11", "v2rayngvpn", "Napsternetv_config", "anti_filter_v2ray",
    "Freedom_v2ray", "Free_Internet_iran", "v2ray_sub", "FreeProxyVless",
    "ShadowrocketConfig", "TG_V2ray_Pool", "Global_Proxy_V2ray", "vpnfail_v2ray"
]

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
