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
    https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt
    https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt
    https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix
    https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/all_configs.txt
    https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt
    https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt
    https://openproxylist.com/v2ray/rawlist/text
    https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs_tested.txt
    https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt
    https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/cloudflare-base64.txt
    https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html
    https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat
    https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt
    https://raw.githubusercontent.com/v2FreeHub/v2hub-configs/refs/heads/main/Sub-AutoUpdate
    https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt
    https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt
    https://raw.githubusercontent.com/luxxuria/harvester/refs/heads/main/speed_tested.txt
    https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt
    https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt
    https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt
    https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt
    https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt
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
