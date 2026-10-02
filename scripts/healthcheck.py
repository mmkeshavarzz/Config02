import ssl
import time
import socket

GLOBAL_SOCKET_TIMEOUT = 2.5
TLS_PROBE_TIMEOUT = 3.0

BLOCKED_CLOUDFLARE_RANGES = [
    "172.64.", "172.65.", "172.66.", "172.67.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.",
    "104.27.", "104.28.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "198.41.128.", "198.41.129.", "199.232."
]

def evaluate_node_vitality(config: dict) -> dict:
    if not config:
        return None

    host = config["host"]
    port = config["port"]
    sni = config["sni"]
    tls = config["tls"]

    # فیلتر ۱: رد کردن هاست‌های بدون دامنه/آی‌پی یا داخلی
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(bad) for bad in BLOCKED_CLOUDFLARE_RANGES):
            return None
        if ip.startswith(('127.', '10.', '192.168.', '0.', '169.254.')):
            return None
    except Exception:
        return None

    # فیلتر ۲: تست باز بودن سوکت واقعی
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(GLOBAL_SOCKET_TIMEOUT)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
        latency = round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        s.close()
        return None

    # فیلتر ۳: تست پیشرفته TLS 
    if tls in ["tls", "reality"] or port in [443, 8443, 2053, 2083, 2087, 2096]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=sni or host) as ss:
                _ = ss.cipher()
        except Exception:
            s.close()
            return None
    else:
        s.close()

    config["latency"] = latency

    # امتیازدهی هوشمند
    score = latency
    if tls == "reality":
        score -= 250
    elif config["protocol"] == "vless":
        score -= 60
    elif config["protocol"] == "trojan":
        score -= 40
        
    config["score"] = score
    return config
