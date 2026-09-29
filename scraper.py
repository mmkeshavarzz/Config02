import base64
import re
import requests
import time

# 💎 لیست کانال‌های آپدیت شده و فعال تلگرام
CHANNELS = [
    "ConfigV2RayNG", "v2rayshahin", "v2ray_configs_pools", 
    "v2rayngvpn", "Hope_Net", "V2ray_Alpha", 
    "v2ray_outlineir", "Napsternetv_config", "FreeV2rays", 
    "v2ray_free_conf", "filembad", "exclaveVPN", 
    "V2rayConfigList", "vpnfail_v2ray", "V2rayuir", 
    "new_mtproxi2", "v2ray_extractor"
]


configs = []
# یه یوزر ایجنت شیک و مجلسی برای عبور از سد تلگرام 🕵️‍♂️
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# 🪄 الگوی تمیز و ضد باگ (با سه کوتیشن که پایتون گیج نشه)
pattern = r'''(vmess://[^\s<"']+|vless://[^\s<"']+|ss://[^\s<"']+|trojan://[^\s<"']+)'''

print("🔍 در حال پوشیدن لباس استتار و ورود به تلگرام...")

for ch in CHANNELS:
    try:
        url = f"https://t.me/s/{ch}"
        res = requests.get(url, headers=headers, timeout=15)
        
        if res.status_code == 200:
            found = re.findall(pattern, res.text)
            cleaned_configs = [c.strip() for c in found]
            print(f"📡 کانال {ch}: تونستم {len(cleaned_configs)} تا کانفیگ گیر بیارم.")
            configs.extend(cleaned_configs)
        else:
            print(f"⚠️ اوه اوه! کانال {ch} در رو رومون بست. (وضعیت: {res.status_code})")
            
        # مکث ۱ ثانیه‌ای برای حفظ ادب پروتکل اینترنت
        time.sleep(1)
        
    except Exception as e:
        print(f"❌ نتونستم به کانال {ch} وصل بشم! دلیل: {e}")

# حذف تکراری‌ها
unique_configs = list(set(configs))
print(f"\n🎉 در مجموع {len(unique_configs)} کانفیگ یونیک پیدا شد.")

# سوپاپ اطمینان: اگه هیچی هم پیدا نشد فایل خالی نمونه
if not unique_configs:
    print("⚠️ کانفیگی پیدا نشد! ساخت کانفیگ فال‌بک...")
    final_raw = "# No configs found today.\nvmess://dummy_fallback_config"
else:
    final_raw = "\n".join(unique_configs)

# تبدیل به Base64 استاندارد کلاینت‌های V2Ray
final_b64 = base64.b64encode(final_raw.encode("utf-8")).decode("utf-8")

# ثبت پیروزمندانه در فایل sub.txt
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(final_b64)

print("✅ ماموریت با موفقیت انجام شد و فایل sub.txt با اقتدار ساخته شد! 🚀")
