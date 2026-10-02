"""
Advanced Health Check Engine for mmkeshavarzz/v2ray-configs
Based on Multi-Round Real Proxied Traffic & Virtual GFW Heuristics.

Features:
- Spawns true Xray-core subprocesses in dynamically batched loopbacks.
- Enforces 3 independent rounds against rotating real endpoints.
- Pre-filters configs using Iran Virtual GFW heuristics (SNI, Port, Reality checks).
- Full compatibility with raw configuration dictionaries and URI links.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple
from urllib.parse import urlparse, parse_qs, unquote


# ==============================================================================
# 1. تنظیمات شبیه‌ساز فیلترینگ ایران و اعتبارسنجی شبکه
# ==============================================================================

# کلمات و دامنه‌هایی که در شبکه ملی و اپراتورهای ایران قطعا مسدود/دراپ می‌شوند
IRAN_FILTERED_KEYWORDS = [
    "google", "youtube", "instagram", "facebook", "twitter", "x.com",
    "telegram", "whatsapp", "tiktok", "netflix", "pornhub", "xvideos",
    "workers.dev", "pages.dev", "github.io"
]

TRASH_SNI_HOSTS = {
    "127.0.0.1", "localhost", "example.com", "test.com", "1.1.1.1", "8.8.8.8"
}

BLOCKED_IP_PREFIXES = (
    "127.", "10.", "192.168.", "0.", "169.254.", "255.", "224.", "100.64."
)

VALID_IRAN_PORTS = {
    443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082, 2086, 2095
}


def is_blocked_in_iran(sni: str, host: str) -> bool:
    """تشخیص دامنه‌های مسدود در لایه SNI فیلترینگ ایران"""
    target = (sni or host or "").lower().strip()
    if not target or target in TRASH_SNI_HOSTS:
        return True

    for keyword in IRAN_FILTERED_KEYWORDS:
        if keyword in target:
            return True

    # اگر ارتباط TLS با یک آی‌پی خام بدون SNI مناسب باشد، دراپ می‌شود
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return True

    return False


def validate_reality_params(raw_link: str) -> bool:
    """بررسی جامع پارامترهای ضروری پروتکل Reality"""
    try:
        parsed = urlparse(raw_link)
        q = parse_qs(parsed.query)
        sec = q.get("security", [""])[0].lower()
        if sec == "reality":
            pbk = q.get("pbk", [""])[0]
            sni = q.get("sni", [""])[0].lower()
            if not pbk or len(pbk) < 35:
                return False
            if is_blocked_in_iran(sni, sni):
                return False
        return True
    except Exception:
        return False


def prefilter_node(config: dict) -> bool:
    """فیلتر سریع قبل از ساخت کانفیگ Xray برای صرفه‌جویی شدید در مصرف CPU"""
    if not config:
        return False

    raw_link = config.get("raw", "")
    host = config.get("host", "").strip()
    port = config.get("port", 443)
    sni = config.get("sni", "").strip()
    tls = config.get("tls", "none").lower()
    net = config.get("network", "tcp").lower()

    try:
        port = int(port)
        if port not in VALID_IRAN_PORTS:
            return False
    except Exception:
        return False

    if tls in ["tls", "reality"] or net in ["ws", "grpc"]:
        if is_blocked_in_iran(sni, host):
            return False

    if tls == "reality" and not validate_reality_params(raw_link):
        return False

    # بررسی صحت آدرس و عدم اشاره به شبکه داخلی
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(prefix) for prefix in BLOCKED_IP_PREFIXES):
            return False
    except Exception:
        return False

    return True


# ==============================================================================
# 2. مدیریت فرآیند تست واقعی Xray-Core (Rule 14 Architecture)
# ==============================================================================

class TestEndpoint(NamedTuple):
    host: str
    path: str
    statuses: tuple[int, ...]


TEST_ENDPOINTS: tuple[TestEndpoint, ...] = (
    TestEndpoint("cp.cloudflare.com", "/generate_204", (204,)),
    TestEndpoint("www.gstatic.com", "/generate_204", (204,)),
    TestEndpoint("captive.apple.com", "/hotspot-detect.html", (200,)),
)

ENDPOINT_CHECK_TIMEOUT = 8.0
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

ROUNDS = 3                 # تعداد دفعاتی که نود باید بدون خطا پاسخ دهد
REQUEST_TIMEOUT = 4.0      # ۴ ثانیه حداکثر تایم‌اوت مجاز درخواست آزمایشی
BATCH_SIZE = 64            # سایز مناسب و سبک برای جلوگیری از کرش Xray در اکشنز
PROBE_WORKERS = 32         # تعداد تست‌های همزمان داخل هر بچ
PORT_RESERVE_ATTEMPTS = 3
STARTUP_TIMEOUT = 12.0     # زمان انتظار برای بالا آمدن اینباندها
SHUTDOWN_TIMEOUT = 5.0
PAUSE_BETWEEN_ROUNDS = 2.0


class HealthCheckError(RuntimeError):
    pass


def reserve_ports(count: int) -> list[int]:
    """تخصیص امن پورت‌های آزاد لوپ‌بک از سیستم‌عامل"""
    for attempt in range(PORT_RESERVE_ATTEMPTS):
        holders: list[socket.socket] = []
        try:
            for _ in range(count):
                holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                holder.bind(("127.0.0.1", 0))
                holders.append(holder)
            ports = [h.getsockname()[1] for h in holders]
            if len(set(ports)) == count:
                return ports
        except OSError:
            if attempt == PORT_RESERVE_ATTEMPTS - 1:
                raise
        finally:
            for holder in holders:
                holder.close()
    raise HealthCheckError(f"Could not reserve {count} free loopback ports")


def config_dict_to_outbound(config: dict, tag: str) -> dict:
    """تبدیل دیکشنری مشخصات نود به ساختار استاندارد Outbound در هسته Xray"""
    protocol = config.get("protocol", "").lower()
    host = config.get("host", "")
    port = int(config.get("port", 443))
    raw_link = config.get("raw", "")
    parsed = urlparse(raw_link)
    query = parse_qs(parsed.query)

    uuid = parsed.username or config.get("id", "")
    sni = query.get("sni", [config.get("sni", "")])[0]
    security = query.get("security", [config.get("tls", "none")])[0].lower()
    net = query.get("type", [config.get("network", "tcp")])[0].lower()
    path = query.get("path", [config.get("path", "/")])[0]
    host_header = query.get("host", [""])[0]

    outbound: dict = {
        "tag": tag,
        "protocol": protocol,
        "settings": {},
        "streamSettings": {
            "network": net,
            "security": security if security in ["tls", "reality"] else "none"
        }
    }

    # پروتکل‌های مختلف
    if protocol == "vless":
        outbound["settings"] = {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": query.get("encryption", ["none"])[0],
                    "flow": query.get("flow", [""])[0]
                }]
            }]
        }
    elif protocol == "vmess":
        outbound["settings"] = {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "alterId": 0,
                    "security": "auto"
                }]
            }]
        }
    elif protocol == "trojan":
        outbound["settings"] = {
            "servers": [{
                "address": host,
                "port": port,
                "password": uuid
            }]
        }
    elif protocol == "shadowsocks":
        method = query.get("method", ["aes-128-gcm"])[0]
        outbound["settings"] = {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": uuid
            }]
        }

    # تنظیمات Stream
    stream = outbound["streamSettings"]
    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": sni or host,
            "allowInsecure": True
        }
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "publicKey": query.get("pbk", [""])[0],
            "shortId": query.get("sid", [""])[0],
            "spiderX": query.get("spx", ["/"])[0],
            "fingerprint": query.get("fp", ["chrome"])[0]
        }

    if net == "ws":
        stream["wsSettings"] = {
            "path": path,
            "headers": {"Host": host_header or sni or host}
        }
    elif net == "grpc":
        service_name = query.get("serviceName", [""])[0]
        stream["grpcSettings"] = {
            "serviceName": service_name,
            "multiMode": True
        }

    return outbound


def _build_batch_config(batch: list[dict], ports: list[int]) -> dict:
    """تولید کانفیگ نهایی چنداینباندی برای ارسال به هسته Xray"""
    inbounds: list[dict] = []
    outbounds: list[dict] = [{"tag": "block", "protocol": "blackhole"}]
    rules: list[dict] = []

    for index, node in enumerate(batch):
        in_tag = f"in-{index}"
        out_tag = f"out-{index}"
        inbounds.append({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": ports[index],
            "protocol": "http",
            "settings": {}
        })
        outbounds.append(config_dict_to_outbound(node, out_tag))
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "block"})

    return {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules}
    }


def _wait_until_listening(ports: list[int], deadline: float, process: subprocess.Popen) -> bool:
    for port in ports:
        while True:
            if process.poll() is not None:
                return False
            if time.monotonic() > deadline:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    break
            except OSError:
                time.sleep(0.04)
    return True


def usable_endpoints() -> list[TestEndpoint]:
    usable: list[TestEndpoint] = []
    for endpoint in TEST_ENDPOINTS:
        conn = http.client.HTTPSConnection(endpoint.host, 443, timeout=ENDPOINT_CHECK_TIMEOUT)
        try:
            conn.request("GET", endpoint.path, headers={"User-Agent": USER_AGENT, "Connection": "close"})
            resp = conn.getresponse()
            resp.read()
            if resp.status in endpoint.statuses:
                usable.append(endpoint)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return usable


def _probe_proxy(port: int, endpoint: TestEndpoint) -> tuple[bool, float]:
    """ارسال درخواست HTTP واقعی از طریق اینباند لوپ‌بک با استفاده از CONNECT Tunnel"""
    started = time.monotonic()
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT)
    try:
        conn.set_tunnel(endpoint.host, 443)
        conn.request("GET", endpoint.path, headers={"User-Agent": USER_AGENT, "Connection": "close"})
        resp = conn.getresponse()
        resp.read()
        elapsed = (time.monotonic() - started) * 1000.0
        return (resp.status in endpoint.statuses), round(elapsed, 2)
    except Exception:
        return False, 9999.0
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _run_batch(xray: str, batch: list[dict], directory: str, label: str, endpoint: TestEndpoint) -> dict[int, float]:
    if not batch:
        return {}
    try:
        ports = reserve_ports(len(batch))
    except Exception:
        return {}

    cfg = _build_batch_config(batch, ports)
    cfg_path = os.path.join(directory, f"{label}.json")
    with open(cfg_path, "w", encoding="utf-8") as h:
        json.dump(cfg, h, ensure_ascii=False)

    log_path = os.path.join(directory, f"{label}.log")
    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            [xray, "run", "-c", cfg_path],
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT
        )
        try:
            deadline = time.monotonic() + STARTUP_TIMEOUT
            if not _wait_until_listening([ports[0], ports[-1]], deadline, proc):
                return {}

            with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
                results = list(pool.map(lambda i: _probe_proxy(ports[i], endpoint), range(len(batch))))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    return {i: lat for i, (ok, lat) in enumerate(results) if ok}


# ==============================================================================
# 3. توابع ارزیابی سازگار با ساختار پروژه شما
# ==============================================================================

def check_nodes_pipeline(xray_path: str, configs: list[dict]) -> list[dict]:
    """
    اجرای کل پروسه چک سلامتی سه‌مرحله‌ای (معادل تابع check در فایل نمونه)
    """
    if not configs:
        return []

    # مرحله ۱: پالایش با فیلترچی مجازی ایران
    filtered = [cfg for cfg in configs if prefilter_node(cfg)]
    print(f"[*] Pre-filter pass: {len(filtered)}/{len(configs)} nodes survived Iran-GFW heuristics.")

    if not filtered:
        return []

    endpoints = usable_endpoints()
    if not endpoints:
        print("[!] No test endpoints available. Falling back to input.")
        return filtered

    with tempfile.TemporaryDirectory(prefix="xray-healthcheck-") as directory:
        latencies: dict[int, list[float]] = {i: [] for i in range(len(filtered))}
        survivors = set(range(len(filtered)))

        for r in range(1, ROUNDS + 1):
            ep = endpoints[(r - 1) % len(endpoints)]
            passed_in_round: set[int] = set()

            for start in range(0, len(filtered), BATCH_SIZE):
                batch = filtered[start : start + BATCH_SIZE]
                label = f"r{r}-b{start // BATCH_SIZE}"
                batch_res = _run_batch(xray_path, batch, directory, label, ep)
                for offset, latency in batch_res.items():
                    idx = start + offset
                    passed_in_round.add(idx)
                    latencies[idx].append(latency)

            survivors &= passed_in_round
            print(f"[*] Round {r}/{ROUNDS} via {ep.host}: {len(passed_in_round)}/{len(filtered)} passed | Total Perfect: {len(survivors)}")
            if r < ROUNDS:
                time.sleep(PAUSE_BETWEEN_ROUNDS)

    final_survivors: list[dict] = []
    for idx in survivors:
        node = filtered[idx]
        median_lat = round(statistics.median(latencies[idx]), 1)
        node["latency"] = median_lat

        # سیستم امتیازدهی برای بالا آوردن کانفیگ‌های مناسب ایران در تاپ ۱۰۰
        score = median_lat
        tls = node.get("tls", "").lower()
        protocol = node.get("protocol", "").lower()
        if tls == "reality":
            score -= 250
        elif protocol == "vless":
            score -= 100
        elif protocol == "trojan":
            score -= 50
        node["score"] = score
        final_survivors.append(node)

    # مرتب‌سازی بر اساس بهترین امتیاز
    final_survivors.sort(key=lambda x: x.get("score", 9999))
    return final_survivors


def evaluate_node_vitality(config: dict) -> dict | None:
    """
    تابع پشتیبان سازگار با منطق تک‌نود (Fallback) در صورتی که سیستم نخواهد بچ‌های Xray بزند
    """
    if not prefilter_node(config):
        return None
    return config
