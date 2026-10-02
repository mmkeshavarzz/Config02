import os
import requests

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
