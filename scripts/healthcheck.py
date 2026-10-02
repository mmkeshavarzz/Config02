import ssl
import time
import socket
from urllib.parse import urlparse, parse_qs

# سروری که از دیتاسنتر گیت‌هاب بیش از ۰.۸ ثانیه طول بکشه، توی ایران عملاً مرده‌ست!
MAX_ACCEPTABLE_TCP_LATENCY = 0.8  

BLOCKED_IP_PREFIXES = (
    "127.", "10.", "192.168.", "0.", "169.254.", "255."
)

# دامنه‌های زباله و سوخته
TRASH_SNI_HOSTS = {
    "127.0.0.1", "localhost", "example.com", "test.com"
}

def validate_reality_config(raw_link: str) -> bool:
    """بررسی تخصصی پارامترهای Reality برای اطمینان از اصالت کانفیگ"""
    try:
        parsed = urlparse(raw_link)
        q = parse_qs(parsed.query)
        sec = q.get("security", [""])[0].lower()
        if sec == "reality":
            pbk = q.get("pbk", [""])[0]
            sni = q.get("sni", [""])[0]
            fp = q.get("fp", ["chrome"])[0]
            # کلید عمومی و اس‌ان‌آی برای ریالیتی الزامی و حیاتی هستند
            if not pbk or len(pbk) < 35 or not sni or sni in TRASH_SNI_HOSTS:
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

    # ۱. اعتبارسنجی اولیه پورت
    try:
        port = int(port)
        if port <= 0 or port > 65535:
            return None
    except Exception:
        return None

    # ۲. فیلتر کردن ریالیتی‌های فیک یا ناقص
    if tls == "reality" and not validate_reality_config(raw_link):
        return None

    # ۳. فیلتر SNI نامعتبر
    if sni and sni in TRASH_SNI_HOSTS:
        return None

    # ۴. ریزالو DNS و حذف IPهای لوکال
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(prefix) for prefix in BLOCKED_IP_PREFIXES):
            return None
    except Exception:
        return None

    # ۵. تست اتصال واقعی TCP با سخت‌گیری بالا
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(MAX_ACCEPTABLE_TCP_LATENCY)
    start_time = time.perf_counter()

    try:
        sock.connect((ip, port))
        latency = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception:
        sock.close()
        return None

    # اگر پورت TLS عادی بود (غیر Reality)، هندشیک سریع برای تست
    if tls == "tls" and port in [443, 8443, 2053, 2083, 2087, 2096]:
        try:
            target_sni = sni if sni else host
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(0.8)
            with ctx.wrap_socket(sock, server_hostname=target_sni) as ss:
                if not ss.cipher():
                    return None
        except Exception:
            sock.close()
            return None
    else:
        # برای ریالیتی یا سایر موارد صرفاً اتصال باز سوکت تایید شد
        try:
            sock.close()
        except Exception:
            pass

    config["latency"] = latency

    # سیستم امتیازدهی دقیق:
    # اولویت بالا به Reality و Vless با کمترین پینگ
    score = latency
    if tls == "reality":
        score -= 250
    elif protocol == "vless":
        score -= 150
    elif protocol == "trojan":
        score -= 80
    elif protocol == "vmess":
        score += 80

    config["score"] = score
    return config
