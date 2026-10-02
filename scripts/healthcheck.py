import ssl
import time
import socket
from urllib.parse import urlparse, parse_qs

# محدودیت تایم‌اوت سخت‌گیرانه برای حذف سرورهای کند و نیمه‌جان
GLOBAL_SOCKET_TIMEOUT = 1.8
TLS_PROBE_TIMEOUT = 2.0

# رنج‌های آی‌پی فیلترشده/ترافیک‌کُش در ایران (کلودفلر، هتزنر بلوک‌شده و رنج‌های فیک)
BLOCKED_RANGES = [
    "172.64.", "172.65.", "172.66.", "172.67.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.",
    "104.27.", "104.28.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "198.41.128.", "198.41.129.", "199.232.",
    "127.", "10.", "192.168.", "0.", "169.254."
]

# دامنه‌های فیک یا اسپم که روی ایران بسته‌اند
INVALID_SNI_HOSTS = ["127.0.0.1", "localhost", "example.com", "google.com"]


def parse_and_verify_reality_parameters(raw_link: str) -> bool:
    """کانفیگ ریالیتی بدون کلید پابلیک یا بدون SNI معتبر، 100% پینگ -1 می‌دهد."""
    try:
        parsed = urlparse(raw_link)
        q = parse_qs(parsed.query)
        sec = q.get("security", [""])[0].lower()
        if sec == "reality":
            pbk = q.get("pbk", [""])[0]
            sni = q.get("sni", [""])[0]
            if not pbk or not sni or len(pbk) < 30:
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

    # ۱. اعتبارسنجی پارامترهای ضروری Reality
    if tls == "reality":
        if not parse_and_verify_reality_parameters(raw_link):
            return None

    # ۲. فیلتر پورت‌های نامعتبر
    if port <= 0 or port > 65535:
        return None

    # ۳. فیلتر SNI نامعتبر
    if sni and sni in INVALID_SNI_HOSTS:
        return None

    # ۴. ریزالو DNS و بررسی آی‌پی
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(bad) for bad in BLOCKED_RANGES):
            return None
    except Exception:
        return None

    # ۵. تست اتصال فیزیکی سوکت با تایم‌اوت فشرده
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(GLOBAL_SOCKET_TIMEOUT)
    start_time = time.perf_counter()

    try:
        sock.connect((ip, port))
        latency = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception:
        sock.close()
        return None

    # ۶. بررسی هندشیک زنده TLS (در صورت نیاز)
    if tls in ["tls", "reality"] or port in [443, 8443, 2053, 2083, 2087, 2096]:
        try:
            target_sni = sni if (sni and not sni.replace(".", "").isdigit()) else host
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(TLS_PROBE_TIMEOUT)
            with ctx.wrap_socket(sock, server_hostname=target_sni) as ss:
                cipher_used = ss.cipher()
                if not cipher_used:
                    return None
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return None
    else:
        try:
            sock.close()
        except Exception:
            pass

    config["latency"] = latency

    # ۷. فرمول رتبه‌بندی کیفی برای شبکه ایران:
    # کانفیگ با پینگ زیر ۴۰۰ میلی‌ثانیه و Reality بالاترین اولویت را دارد
    score = latency
    if tls == "reality":
        score -= 300
    elif config.get("protocol") == "vless":
        score -= 100
    elif config.get("protocol") == "trojan":
        score -= 50

    config["score"] = score
    return config
