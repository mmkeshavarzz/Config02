import os
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from nodes import harvest_raw_configs_from_sources
from transform import parse_config_schema, attach_country_codes
from healthcheck import evaluate_node_vitality

WORKER_THREADS = 100
TARGET_ELITE_COUNT = 100
MAX_ACCEPTABLE_LATENCY_MS = 1200.0  # سقف مجاز تاخیر؛ بالاتر از این زباله‌دان تاریخ است!

def send_telegram_alert(raw_count: int, alive_count: int, elite_count: int):
    token = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHANNEL") or os.getenv("TG_CHANNEL_ID")
    
    if not token or not chat_id:
        print("⚠️ Telegram secrets not found. Skipping telegram notification.")
        return

    REPO_NAME = os.getenv("GITHUB_REPOSITORY", "mmkeshavarzz/v2ray-configs")
    BRANCH = "main"

    raw_top100_url = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/top100.txt"
    raw_top10_url = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/top10.txt"
    cdn_top100_url = f"https://cdn.jsdelivr.net/gh/{REPO_NAME}@{BRANCH}/top100.txt"
    vless_sub = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/protocols/vless.txt"
    raw_sub_url = f"https://raw.githubusercontent.com/{REPO_NAME}/{BRANCH}/sub.txt"

    subscription_message = (
        "🚀 *تصفیه‌خانه ضد زامبی: لیست نخبگان*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 *گزارش فیلتراسیون عمیق:*\n"
        f"▫️ کل کانفیگ‌های شکارشده: `{raw_count}`\n"
        f"▫️ نجات‌یافتگان از تست سخت TLS: `{alive_count}`\n"
        f"▫️ گلچین نهایی بدون پینگ منفی: `{elite_count}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔗 *لینک‌های سابسکریپشن فعال:*\n\n"
        "⚡ *لینک ضدفیلتر jsDelivr (تاپ 100 پیشنهادی):*\n"
        f"`{cdn_top100_url}`\n\n"
        "🔥 *لینک 10 موشک بالستیک (Top 10):*\n"
        f"`{raw_top10_url}`\n\n"
        "🛰️ *لینک مستقیم گیت‌هاب (Top 100):*\n"
        f"`{raw_top100_url}`\n\n"
        "💎 *اختصاصی VLESS Reality & TCP:*\n"
        f"`{vless_sub}`\n\n"
        "📦 *مخزن جامع فعال (Full Sub):*\n"
        f"`{raw_sub_url}`\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 *نکته:* هر ساعت به صورت خودکار بهینه‌سازی می‌شود. نوش جان! 🍹"
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
        print(f"❌ Error sending telegram message: {e}")

def main():
    print("=" * 65)
    print("🚀 ANTI-ZOMBIE ENGINE (MODULAR): Starting Full Scan & Deep Filter")
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

    alive_pool = [node for node in alive_pool if node.get("latency", 9999) < MAX_ACCEPTABLE_LATENCY_MS]
    print(f"⚡ Filtered Nodes with Low Latency (<{int(MAX_ACCEPTABLE_LATENCY_MS)}ms): {len(alive_pool)}")

    if not alive_pool:
        print("⚠️ Warning: No nodes survived the strict vitality check.")
        return

    # مرتب‌سازی بر اساس امتیاز کیفی
    alive_pool.sort(key=lambda x: x["score"])
    
    # ‼️ این خط نجات‌بخش است: اول ریبرندینگ انجام میشه، بعد ذخیره فایل!
    print("💅 Attaching country codes and rebranding to @Raydikalx style...")
    attach_country_codes(alive_pool)

    verified_top100 = alive_pool[:TARGET_ELITE_COUNT]
    print(f"🎯 Successfully Selected Elite Nodes: {len(verified_top100)}")

    def write_b64(filename, items):
        content = "\n".join([x["raw"] for x in items])
        with open(filename, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(content.encode("utf-8")).decode("utf-8"))

    write_b64("top100.txt", verified_top100)
    write_b64("top10.txt", verified_top100[:10])
    write_b64("sub.txt", alive_pool)

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
    print("🏁 Processing finished successfully! Zero-zombie era has begun.")

if __name__ == "__main__":
    main()
