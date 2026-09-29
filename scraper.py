import base64
import re
import requests
import time

# 💎 لیست کانال‌های آپدیت شده (شهریور/مهر 1405)
# سعی کردم کانال‌هایی رو بذارم که اخیرا فعالیت داشتن و ساب‌های بالایی دارن
CHANNELS = [
    "ConfigV2RayNG",
    "v2rayshahin",
    "v2ray_configs_pools",
    "v2rayngvpn", 
    "Hope_Net",
    "V2ray_Alpha",
    "v2ray_outlineir",
    "Napsternetv_config",
    "FreeV2rays",
    "v2ray_free_conf"
]

configs = []
# یه یوزر ایجنت خفن که تلگرام فکر کنه ما یه آدمیم پشت کروم، نه یه ربات پایتونی! 🕵️‍♂️
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# الگوی جادویی ما برای شکار کانفیگ‌ها
pattern = r"(vmess://[^\s<"']+ |vless://[^\s<"']+ |ss://[^\s<"']+ |trojan://[^\s<"']+ )"

print("🔍 در حال پوشیدن لباس استتار و ورود به تلگرام...")

for ch in CHANNELS:
    try:
        url = f"https://t.me/s/{ch}"
        # گذاشتن تایم‌اوت منطقی که اگه سایت بالا نیومد، گیر نکنه
        res = requests.get(url, headers=headers, timeout=15)
        
        if res.status_code == 200:
            found = re.findall(pattern, res.text)
            # یه کم تمیزکاری که اگه آخر لینک‌ها چیزی چسبیده بود پاک بشه
            cleaned_configs = [c.strip() for c in found]
            print(f"📡 کانال {ch}: تونستم {len(cleaned_configs)} تا کانفیگ گیر بیارم.")
            configs.extend(cleaned_configs)
        else:
            print(f"⚠️ اوه اوه! کانال {ch} در رو رومون بست. (وضعیت: {res.status_code})")
            
        # یه مکث کوچیک بین هر درخواست که تلگرام بلاکمون نکنه (مثل یه انسان باشخصیت رفتار کنیم 🧐)
        time.sleep(1)
        
    except Exception as e:
        print(f"❌ نتونستم به کانال {ch} وصل بشم! دلیل: {e}")

# حذف کانفیگ‌های تکراری (کسی از جنس بنجل دوبله خوشش نمیاد!)
unique_configs = list(set(configs))
print(f"\n🎉 ایول! در مجموع {len(unique_configs)} تا کانفیگ ناب و یونیک شکار کردیم.")

# 🛡️ سپر محافظتی در برابر خطای ۱۲۸ گیت‌هاب (همون بچه زرنگه که دست خالی برنمیگرده)
if not unique_configs:
    print("⚠️ ای بابا، امروز کاسبی خراب بود و هیچی پیدا نکردیم! دارم کانفیگ نجات رو میسازم...")
    final_raw = "# No configs found today. Telegram might be acting up!\nvmess://dummy_fallback_config"
else:
    final_raw = "\n".join(unique_configs)

# تبدیل دیتای خام به بیس۶۴، همونطوری که کلاینت‌ها دوست دارن ببلعنش
final_b64 = base64.b64encode(final_raw.encode("utf-8")).decode("utf-8")

# نوشتن فایل نهایی با اقتدار
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(final_b64)

print("✅ ماموریت انجام شد! فایل sub.txt با موفقیت پیچیده شد و آماده‌ی ارساله. 🚀")
