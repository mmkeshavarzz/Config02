import requests
import re
import base64

# لیست کانال‌هایی که می‌خوایم غارتشون کنیم 🏴‍☠️
CHANNELS = ["v2ray_configs_channel", "free_v2ray_worlds"] 
CONFIG_REGEX = r'(vmess|vless|trojan|ss)://[a-zA-Z0-9@:%._\+~#=/?&A-Za-z0-9\-]+'

def get_configs():
    all_configs = []
    for channel in CHANNELS:
        try:
            # نیازی به توکن نیست، از نسخه وب تلگرام می‌دزدیم! 🤫
            url = f"https://t.me/s/{channel}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                configs = re.findall(CONFIG_REGEX, response.text)
                all_configs.extend(configs)
        except Exception as e:
            print(f"Error checking {channel}: {e}")
    
    # اینجا می‌تونی یه فیلتر بذاری که آی‌پی‌های ایران رو حذف کنه 
    # (معمولا کانفیگ‌های پابلیک خارجی، آی‌پی ایران ندارن)
    
    return list(set(all_configs))

if __name__ == "__main__":
    configs = get_configs()
    if configs:
        # تبدیل به Base64 برای لینک ساب
        raw_text = "\n".join(configs)
        encoded = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
        
        with open("sub.txt", "w") as f:
            f.write(encoded)
        print("✅ صید امروز با موفقیت انجام شد! کانفیگ‌ها ذخیره شدند.")
