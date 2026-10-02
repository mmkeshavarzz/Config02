import ssl
import time
import socket
import re
from urllib.parse import urlparse, parse_qs

# ==============================================================================
# 🛑 شبیه‌ساز فیلترینگ ایران (Virtual GFW)
# ==============================================================================
MAX_ACCEPTABLE_TCP_LATENCY = 0.6  # سخت‌گیری وحشتناک روی پینگ (۶۰۰ میلی‌ثانیه برای گیت‌هاب)

# کلمات و دامنه‌هایی که در ایران قطعا در لایه SNI مسدود می‌شوند
IRAN_FILTERED_KEYWORDS = [
    "google", "youtube", "instagram", "facebook", "twitter", "x.com", 
    "telegram", "whatsapp", "tiktok", "netflix", "pornhub", "xvideos",
    "workers.dev", "pages.dev", "github.io" # به شدت روی کلودفلر ورکرز در ایران حساسیت هست
]

# دامنه‌های زباله که فقط برای تست محلی بودن و در اینترنت واقعی کار نمی‌کنند
TRASH_SNI_HOSTS = {
    "127.0.0.1", "localhost", "example.com", "test.com", "1.1.1.1", "8.8.8.8"
}

BLOCKED_IP_PREFIXES = (
    "127.", "10.", "192.168.", "0.", "169.254.", "255.", "224.", "100.64."
)

def is_blocked_in_iran(sni: str, host: str) -> bool:
    """بررسی اینکه آیا این دامنه یا SNI در ایران مسدود است یا خیر"""
    target = (sni or host).lower()
    if not target or target in TRASH_SNI_HOSTS:
        return True
    
    # اگر در نام دامنه کلمات فیلتر شده وجود داشته باشد
    for keyword in IRAN_FILTERED_KEYWORDS:
        if keyword in target:
            return True
            
    # اگر فقط آی‌پی خالی باشه و کاربر انتظار TLS داشته باشه، ایران دراپ می‌کنه
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return True
        
    return False

def validate_reality_config(raw_link: str) -> bool:
    """بررسی تخصصی پارامترهای Reality (حیاتی برای ایران)"""
    try:
        parsed = urlparse(raw_link)
        q = parse_qs(parsed.query)
        sec = q.get("security", [""])[0].lower()
        if sec == "reality":
            pbk = q.get("pbk", [""])[0]
            sni = q.get("sni", [""])[0].lower()
            # کلید عمومی باید حداقل ۳۵ کاراکتر باشد
            if not pbk or len(pbk) < 35:
                return False
            # آیا اس‌ان‌آی برای ریالیتی در ایران قفل است؟
            if is_blocked_in_iran(sni, sni):
                return False
        return True
    except Exception:
        return False

def evaluate_node_vitality(config: dict) -> dict:
    if not config:
        return None

    raw_link = config.get("raw", "")
    host = config.get("host", "").strip()
    port = config.get("port", 443)
    sni = config.get("sni", "").strip()
    tls = config.get("tls", "none").lower()
    protocol = config.get("protocol", "").lower()
    net = config.get("network", "tcp").lower()

    # ۱. اعتبارسنجی اولیه پورت‌های رایج و منطقی
    try:
        port = int(port)
        if port not in [443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082, 2086, 2095]:
            return None # دور ریختن پورت‌های عجیب که در ایران مسدودند
    except Exception:
        return None

    # ۲. عبور از فیلترچی مجازی ایران (Virtual GFW)
    if tls in ["tls", "reality"] or net in ["ws", "grpc"]:
        if is_blocked_in_iran(sni, host):
            return None

    # ۳. فیلتر کردن ریالیتی‌های فیک یا ناقص
    if tls == "reality" and not validate_reality_config(raw_link):
        return None

    # ۴. ریزالو DNS (تست اینکه دامنه اصلا وجود خارجی دارد یا نه)
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(prefix) for prefix in BLOCKED_IP_PREFIXES):
            return None
    except Exception:
        return None

    # ۵. تست اتصال واقعی TCP با بی‌رحمی تمام (تایم‌اوت ۰.۶ ثانیه)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(MAX_ACCEPTABLE_TCP_LATENCY)
    start_time = time.perf_counter()

    try:
        sock.connect((ip, port))
        latency = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception:
        sock.close()
        return None  # اگر از گیت‌هاب نتونه سریع وصل شه، تو ایران فاجعه است!

    # ۶. بررسی زنده بودن TLS (غیر از Reality چون ریالیتی به کلاینت‌های غیرمجاز جواب نمیده)
    if tls == "tls" and protocol != "trojan": 
        try:
            target_sni = sni if sni else host
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(0.5)
            with ctx.wrap_socket(sock, server_hostname=target_sni) as ss:
                if not ss.cipher():
                    return None
        except Exception:
            sock.close()
            return None
    else:
        try:
            sock.close()
        except Exception:
            pass

    config["latency"] = latency

    # سیستم امتیازدهی هوشمند (اولویت با پروتکل‌های قدرتمند در ایران)
    score = latency
    if tls == "reality":
        score -= 300  # ریالیتی بهترین عملکرد رو تو ایران داره
    elif net == "ws" and tls == "tls":
        score -= 100  # وب‌سوکت روی TLS هنوز هم جواب میده
    elif protocol == "vless":
        score -= 50
    elif protocol == "vmess":
        score += 150  # ویمس دیگه پیر شده و راحت شناسایی میشه

    config["score"] = score
    return config
