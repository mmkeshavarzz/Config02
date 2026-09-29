import base64
import os
import re
import requests

# لیست کانال‌ها (حتما بدون @ بنویس)
CHANNELS = [
    "v2ray_free_conf",
    "PrivateVPNs",
    "v2rayngvpn",
]

configs = []
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

# پروتکل‌های استاندارد
PATTERN = r"(vmess://[a-zA-Z0-9+=]+|vless://[^\s]+|ss://[^\s]+|trojan://[^\s]+)"

for channel in CHANNELS:
    url = f"https://t.me/s/{channel}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            found = re.findall(PATTERN, response.text)
            configs.extend(found)
            print(f"✅ کانال {channel}: تعداد {len(found)} کانفیگ شکار شد.")
        else:
            print(f"⚠️ کانال {channel} پاسخ نداد (کد {response.status_code})")
    except Exception as e:
        print(f"❌ خطا در اسکرپ {channel}: {e}")

# حذف تکراری‌ها
unique_configs = list(set(configs))
print(f"🎯 مجموع کانفیگ‌های یکتا: {len(unique_configs)}")

# ساخت رشته نهایی
content = "\n".join(unique_configs)
if not content.strip():
    # اگه هیچی پیدا نشد، یه خط کامنت بذار که فایل خالی نمونه و گیت ارور نده!
    content = "# No configs found at this time"

# تبدیل به بیس64
encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")

# ذخیره حتمی در مسیر اصلی
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(encoded_content)

print("🚀 فایل sub.txt با موفقیت ایجاد شد!")
