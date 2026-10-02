<div align="center">

# ⚡ V2Ray High-Availability Auto-Aggregator
### پلتفرم خودکار جمع‌آوری، فیلتراسیون عمیق و سنجش سلامت لحظه‌ای کانفیگ‌ها

<p align="center">
  <img alt="Pipeline Status" src="https://img.shields.io/github/actions/workflow/status/mmkeshavarzz/v2ray-configs/main.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=PIPELINE">
  <img alt="Update Frequency" src="https://img.shields.io/badge/AUTO--UPDATE-EVERY%2015%20MIN-0ea5e9?style=for-the-badge">
  <img alt="GitHub Stars" src="https://img.shields.io/github/stars/mmkeshavarzz/v2ray-configs?style=for-the-badge&color=f59e0b&logo=github">
  <img alt="License" src="https://img.shields.io/badge/LICENSE-MIT-10b981?style=for-the-badge">
</p>

<p>
  <i>کانفیگ‌های فعال به صورت بلادرنگ و با هسته‌های واقعی ارزیابی شده و لینک‌های سابسکریپشن در دسترس قرار می‌گیرند.</i>
</p>

</div>

---

## 🚀 دسترسی سریع — فقط یک خط کپی کنید!

نیازی به کلنجار رفتن با فایل‌های حجیم و کانفیگ‌های سوخته نیست؛ لینک زیر گلچینی از سریع‌ترین و باثبات‌ترین سرورهای تست‌شده است:

### 🏆 لینک سابسکریپشن برگزیده (Top 100 Verified):
```text
https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/top100.txt

---

## 🎛️ دسته‌بندی سابسکریپشن‌ها (Subscription Tiers)

کانفیگ‌ها بر اساس آزمون‌های فنی در دسته‌های زیر تفکیک و ارائه می‌شوند:

| دسته (Tier) | معیار انتخاب | لینک اشتراک مستقیم (Base64) | فرمت Clash / Mihomo | فرمت Sing-box |
| :--- | :--- | :---: | :---: | :---: |
| 🏆 **Verified** | عبور موفق از هر ۳ مرحله تست فعال اتصال (پیشنهادی) | [لینک ساب](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/verified/sub.txt) | [کانفیگ YAML](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/clash/verified.yaml) | [کانفیگ JSON](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/singbox/verified.json) |
| ⚡ **Fast** | دارای پایین‌ترین پینگ و تأخیر زمانی (زیر ۲۰۰ میلی‌ثانیه) | [لینک ساب](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/fast/sub.txt) | [کانفیگ YAML](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/clash/fast.yaml) | [کانفیگ JSON](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/singbox/fast.json) |
| 🛡️ **Secure** | پروتکل‌های مدرن، مقاوم و دارای TLS/Reality | [لینک ساب](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/secure/sub.txt) | [کانفیگ YAML](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/clash/secure.yaml) | [کانفیگ JSON](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/singbox/secure.json) |
| 📦 **All Pool** | تمامی کانفیگ‌های معتبر ساختاری خام | [لینک ساب](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/all/sub.txt) | [کانفیگ YAML](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/clash/all.yaml) | [کانفیگ JSON](https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/main/singbox/all.json) |

---

## 🧪 فرآیند پالایش و تست (The Filtration Funnel)

بزرگ‌ترین مشکل مخازن عمومی، وجود انبوهی از سرورهای ازکارافتاده است. ما به‌جای انتشار آمارهای غیرواقعی، کانفیگ‌ها را از قیف پالایش چهارگانه عبور می‌دهیم:

text
[L0: گردآوری] ──> [L1: پاکسازی و حذف تکراری] ──> [L2: تست پورت TCP] ──> [L3: درخواست واقعی HTTP] ──> انتشار نهایی

### شرح سطوح اعتبارسنجی:

| سطح (Stage) | پرسش کلیدی سیستم | هزینه محاسباتی / عملیاتی |
| :---: | :--- | :--- |
| **L0 / L1** | آیا ساختار URI معتبر است؟ آیا IP و SNI یکتا هستند؟ | بدون سربار شبکه (صرفاً اعتبارسنجی رشته‌ای) |
| **L2** | آیا پورت پروتکل باز است و به TCP Handshake پاسخ می‌دهد؟ | یک اتصال سبک به ازای هر Endpoint یکتا |
| **L3** | آیا دیتا از بستر پروکسی به مقصد می‌رسد؟ | ۳ بار تکرار درخواست واقعی HTTP از تونل رمزنگاری‌شده |
| **Publish** | آیا کلاینت‌های استاندارد فایل خروجی را باز می‌کنند؟ | تست کامپایل با ابزارهای بومی `sing-box check` و `mihomo -t` |

> 💡 **توجه مهندسی:** تنها کانفیگ‌هایی وارد سبد `verified` می‌شوند که در **هر ۳ نوبت تست L3** با موفقیت پاسخ دریافت کرده باشند، نه آن‌هایی که صرفاً یک‌بار به صورت تصادفی وصل شده‌اند.

---

## ⚙️ معماری پایپ‌لاین و مخزن

* **تغییرناپذیری برچسب‌ها (Stable Identity):** عنوان هر سرور با فرمت `{CC} {Flag} | #mmk | {Hash}` بازنویسی می‌شود تا با تغییر سورت، کانفیگ داخل کلاینت کاربر مدام جا‌به‌جا نشود.
* **مهندسی حافظه گیت (Rolling Squash):** برای جلوگیری از افزایش بی‌رویه حجم مخزن ناشی از کامیت‌های پی‌درپی خروجی‌ها، تنها یک کامیت اکتیو نگه داشته می‌شود و تاریخچه سورس حفظ می‌گردد.
* **بدون نیاز به ابزار جانبی:** خروجی‌ها در قالب فایل‌های متنی استاندارد و بدون نیازمندی به فایل‌های استاتیک وب مستقیماً قابل بارگذاری هستند.

---

## ⚖️ سلب مسئولیت (Disclaimer)

تمامی کانفیگ‌های موجود در این مخزن از منابع عمومی اینترنت جمع‌آوری شده‌اند. وضعیت دسترسی سرورها در لحظه اجرای رانر ارزیابی می‌شود و ممکن است بر اساس زیرساخت شبکه و موقعیت جغرافیایی کاربر نتایج متفاوتی حاصل شود.


---

### مرحله بعد چیه؟

همین الان برو این فایل رو بنداز توی مخزنت تا دیگه صفحه اصلیت شبیه سالن انتظار راه‌آهن ساعت ۳ نصفه‌شب نباشه! 🚂✨ 
بعدش برگرد تا اسکریپت پایتونی **پالایش و نام‌گذاری هش‌محور (مرحله L0 و L1)** رو شروع کنیم. آماده‌ای؟
