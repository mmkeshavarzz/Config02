import base64
import re
import requests

# چند تا کانال تست و تضمینی و عمومی
CHANNELS = [
    "v2ray_free_conf",
    "PrivateVPNs",
    "v2rayngvpn",
    "FreelandVpn",
]

configs = []
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

pattern = r"(vmess://[^\s<]+|vless://[^\s<]+|ss://[^\s<]+|trojan://[^\s<]+)"

print("🔍 شروع جستجوی کانفیگ‌ها...")

for ch in CHANNELS:
    try:
        url = f"https://t.me/s/{ch}"
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            found = re.findall(pattern, res.text)
            print(f"📡 کانال {ch}: {len(found)} کانفیگ پیدا شد.")
            configs.extend(found)
        else:
            print(f"⚠️ کانال {ch} وضعیت {res.status_code} داد.")
    except Exception as e:
        print(f"❌ خطای اتصال به {ch}: {e}")

# حذف تکراری‌ها
unique_configs = list(set(configs))
print(f"🎉 کل کانفیگ‌های شکار شده: {len(unique_configs)}")

# نکته حیاتی: حتی اگر هیچی پیدا نشد، یک کانفیگ نمادین بنویس تا فایل خالی نمونه!
if not unique_configs:
    print("⚠️ هیچ کانفیگی پیدا نشد! ساخت کانفیگ نجات...")
    final_raw = "# No configs found\nvmess://dummy_fallback_config"
else:
    final_raw = "\n".join(unique_configs)

# تبدیل به Base64 استاندارد سابسکریپشن
final_b64 = base64.b64encode(final_raw.encode("utf-8")).decode("utf-8")

# نوشتن فایل در شاخه اصلی پروژه (بدون قید و شرط)
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(final_b64)

print("✅ فایل sub.txt با موفقیت و اقتدار کامل ایجاد گردید!")
