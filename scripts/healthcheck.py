import ssl
import time
import socket
from urllib.parse import urlparse, parse_qs

# محدودیت‌های فوق‌العاده سفت‌وسخت: نودهای تنبل به درد ایران نمی‌خورند!
GLOBAL_SOCKET_TIMEOUT = 1.2
TLS_PROBE_TIMEOUT = 1.5

# رنج‌های آی‌پی فیلترشده، رنج‌های CDN مسدود و سوراخ‌های سیاه DPI ایران
BLOCKED_RANGES = (
    "172.64.", "172.65.", "172.66.", "172.67.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.",
    "104.27.", "104.28.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "198.41.128.", "198.41.129.", "199.232.",
    "127.", "10.", "192.168.", "0.", "169.254."
)

# دامنه‌ها و SNIهای فیک، سوخته یا کاملاً مسدود روی شبکه همراه اول/ایرانسل
INVALID_SNI_HOSTS = {
    "127.0.0.1", "localhost", "example.com", "google.com",
    "speedtest.net", "cloudflare.com", "fast.com", "yahoo.com"
}


def parse_and_verify_reality_parameters(raw_link: str) -> bool:
    """کانفیگ Reality بدون کلید معتبر، صد در صد پینگ منفی یک می‌دهد."""
    try:
        parsed = urlparse(raw_link)
        q = parse_qs(parsed.query)
        sec = q.get("security", [""])[0].lower()
        if sec == "reality":
            pbk = q.get("pbk", [""])[0]
            sni = q.get("sni", [""])[0]
            # کلید پابلیک Reality باید رشته معتبر استاندارد باشد
            if not pbk or not sni or len(pbk) < 40 or sni in INVALID_SNI_HOSTS:
                return False
        return True
    except Exception:
        return False


def is_cloudflare_or_blocked_cdn(host: str, ip: str) -> bool:
    """بررسی اینکه سرور متعلق به CDNهای سوخته روی ایران نباشد."""
    if any(ip.startswith(bad) for bad in BLOCKED_RANGES):
        return True
    h = host.lower()
    if "workers.dev" in h or "pages.dev" in h or "cloudflare" in h:
        return True
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
    net_type = config.get("network", "tcp").lower()

    # ۱. پورت‌های مجاز استانداردی که DPI کمتر گیر می‌دهد
    if port not in [443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082, 2086, 2095]:
        # پورت‌های غیراستاندارد معمولاً سرورهای خانگی و مرده هستند
        return None

    # ۲. راستی‌آزمایی پروتکل Reality
    if tls == "reality":
        if not parse_and_verify_reality_parameters(raw_link):
            return None

    # ۳. فیلتر SNI نامعتبر
    if sni and (sni in INVALID_SNI_HOSTS or sni.startswith("104.") or sni.startswith("172.")):
        return None

    # ۴. ریزالو نام دامنه و بررسی آی‌پی علیه رنج‌های سوخته
    try:
        ip = socket.gethostbyname(host)
        if is_cloudflare_or_blocked_cdn(host, ip):
            return None
    except Exception:
        return None

    # ۵. تست اتصال فیزیکی سوکت با تایم‌اوت برق‌آسا (زیر ۱.۲ ثانیه)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(GLOBAL_SOCKET_TIMEOUT)
    start_time = time.perf_counter()

    try:
        sock.connect((ip, port))
        latency = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception:
        sock.close()
        return None

    # ۶. تست عمیق هندشیک TLS و ارسال پروب واقعی
    if tls in ["tls", "reality"] or port in [443, 8443, 2053, 2083, 2087, 2096]:
        try:
            target_sni = sni if (sni and not sni.replace(".", "").isdigit()) else host
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # تنظیم ALPN برای تضمین سازگاری با پروکسی
            try:
                ctx.set_alpn_protocols(['h2', 'http/1.1'])
            except Exception:
                pass

            sock.settimeout(TLS_PROBE_TIMEOUT)
            with ctx.wrap_socket(sock, server_hostname=target_sni) as ss:
                cipher_used = ss.cipher()
                if not cipher_used:
                    return None
                
                # پروب اولیه پروتکل: فرستادن یک درخواست ساده HTTP/Probe برای راستی‌آزمایی حیات سوکت
                if net_type in ["ws", "http"]:
                    probe_payload = f"HEAD / HTTP/1.1\r\nHost: {target_sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    ss.sendall(probe_payload.encode())
                    # اگر پاسخ داد یا حداقل کانکشن فورا ریست نشد یعنی سرور واقعا بیدار است
                    data = ss.recv(64)
                    if not data:
                        return None

        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return None
    else:
        # برای کانفیگ‌های بدون TLS، یک پروب ساده برای اطمینان از بسته نبودن پورت توسط DPI
        try:
            sock.sendall(b"\x05\x01\x00")  # پروب هدر ساده
            sock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return None

    config["latency"] = latency

    # ۷. سیستم امتیازدهی تخصصی برای اینترنت ایران (نودهای Reality و Vless در صدر)
    score = latency
    if tls == "reality":
        score -= 400
    elif protocol == "vless":
        score -= 200
    elif protocol == "trojan":
        score -= 100
    elif protocol == "vmess":
        score += 50  # vmess شانس کمتری در دور زدن DPI جدید دارد

    config["score"] = score
    return config
