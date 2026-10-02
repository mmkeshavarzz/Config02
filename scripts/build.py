import os
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# وارد کردن توابع از ماژول‌های خودمون
from nodes import harvest_raw_configs_from_sources
from transform import parse_config_schema, attach_country_codes
from healthcheck import evaluate_node_vitality

WORKER_THREADS = 40
TARGET_ELITE_COUNT = 100

def send_telegram_alert(raw_count: int, alive_count: int, elite_count: int):
    token = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHANNEL") or os.getenv("TG_CHANNEL_ID")
    
    if not token or not chat_id:
        print("⚠️ سکرت‌های تلگرام پیدا نشدند!")
        return

    REPO_NAME = os.getenv("GITHUB_REPOSITORY", "mmkeshavarzz/v2ray-configs")
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
        "🔗 *لینک‌های سابسکریپشن هوشمند:*\n\n"
        "🚀 *لینک مستقیم گیت‌هاب (Top 100):*\n"
        f"`{raw_top100_url}`\n\n"
        "⚡ *لینک ضدفیلتر (jsDelivr):*\n"
        f"`{cdn_top100_url}`\n\n"
        "💎 *کانفیگ‌های اختصاصی VLESS:*\n"
        f"`{vless_sub}`\n\n"
        "📦 *مخزن جامع فعال (Sub Full):*\n"
        f"`{raw_sub_url}`\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 *آموزش:* لینک‌ها را کپی کرده و در v2rayNG آپدیت کنید! 🚀"
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

def main():
    print("=" * 65)
    print("🚀 ANTI-ZOMBIE ENGINE (MODULAR): Starting Full Scan")
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

    alive_pool.sort(key=lambda x: x["score"])
    verified_top100 = alive_pool[:TARGET_ELITE_COUNT]

    print(f"🎯 Successfully Selected Elite Nodes: {len(verified_top100)}")

    # تولید فایل‌های خروجی Base64
    def write_b64(filename, items):
        content = "\n".join([x["raw"] for x in items])
        with open(filename, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(content.encode("utf-8")).decode("utf-8"))

    write_b64("top100.txt", verified_top100)
    write_b64("top10.txt", verified_top100[:10])
    write_b64("sub.txt", alive_pool)

    attach_country_codes(alive_pool)
    os.makedirs("protocols", exist_ok=True)
    os.makedirs("countries", exist_ok=True)

    protocols_dict = {"vless": [], "vmess": [], "trojan": [], "ss": []}
    countries_dict = {}

    for node in alive_pool:
        proto = node.get("protocol", "vless")
        if proto in protocols_dict:
            protocols_dict[proto].append(node)
        
        c = node.get("country", "OTHER")
        if c not in countries_dict:
            countries_dict[c] = []
        countries_dict[c].append(node)

    for proto_name, items in protocols_dict.items():
        if items:
            write_b64(f"protocols/{proto_name}.txt", items)

    for c_code, items in countries_dict.items():
        if items:
            write_b64(f"countries/{c_code}.txt", items)

    send_telegram_alert(len(raw_candidates), len(alive_pool), len(verified_top100))
    print("🏁 Processing finished successfully!")

if __name__ == "__main__":
    main()
