"""Rule 14: keep only nodes that actually carry traffic.

Reimplements the criterion the upstream project publishes in its own header --
"a real proxied request to https://cp.cloudflare.com/generate_204 succeeded in
ALL 3 independent runs" -- directly against Xray-core rather than a wrapper.

The nodes reaching this stage deliberately carry none of ``fm``, ``dialMode``,
``ech``, ``echOutbound``, ``fp`` or ``cs``: those shape how a connection is made
rather than whether the node works, so the check runs over the core's plain
TLS and transform.finalise adds them to the survivors afterwards.
:func:`preflight` therefore validates every published shape as well as the
tested one, because nothing else in the pipeline ever hands those six to the
core.

Shape of a round: nodes are grouped into batches; each batch becomes one Xray
process with one loopback HTTP inbound per node, routed to that node's outbound.
Every node is then probed concurrently through its own inbound. Three rounds run
and only the intersection survives, because a single run misgrades a substantial
fraction of nodes -- upstream measured 25-64% of working nodes as flaky.

The default outbound is a blackhole, so a node whose routing rule somehow fails
to match cannot fall through to a direct connection and report itself healthy.

Two comparable projects were reviewed for ideas. Delta-Kronecker/V2ray-Config
(src/validator.go) also runs a real proxied request, and its list of test URLs
is where TEST_ENDPOINTS below comes from. itsyebekhe/PSG (main.py) does not
proxy at all -- it checks DNS plus a TCP connect, which cannot tell a live
proxy from any host with an open port.

Three of their techniques are deliberately not used here:

* A TCP-ping prefilter (both projects). Rule 10 points every node at the same
  Cloudflare address, so a TCP connect always succeeds and filters nothing.
* Retrying failed configs (Delta-Kronecker retries in rounds). That is the
  opposite of requiring 3 of 3: a retry hands a flaky node extra chances to
  pass, which is what the intersection exists to stop.
* Static per-protocol field validation (PSG). Already covered -- xray run -test
  validates every config first and the bisect isolates whatever it rejects.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple, Any
from urllib.parse import urlparse, parse_qs

try:
    import transform
    from nodes import Node
except ImportError:
    transform = None
    Node = None


# ==============================================================================
# 🛑 شبیه‌ساز فیلترینگ ایران (Virtual GFW) & اعتبارسنجی‌های تخصصی
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

VALID_IRAN_PORTS = {
    443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082, 2086, 2095
}


def is_blocked_in_iran(sni: str, host: str) -> bool:
    """بررسی اینکه آیا این دامنه یا SNI در ایران مسدود است یا خیر"""
    target = (sni or host or "").lower().strip()
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


def evaluate_node_vitality(config: dict) -> dict | None:
    """ارزیابی جامع و سریع سلامت نود با فیلترهای سبک قبل از ارسال به هسته Xray"""
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
        if port not in VALID_IRAN_PORTS:
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


# ==============================================================================
# 2. مدیریت فرآیند تست واقعی Xray-Core (Rule 14 Architecture)
# ==============================================================================

class TestEndpoint(NamedTuple):
    host: str
    path: str
    statuses: tuple[int, ...]


# One endpoint per round, rotating, so a node has to satisfy three independent
# operators rather than the same target three times.
TEST_ENDPOINTS: tuple[TestEndpoint, ...] = (
    TestEndpoint("cp.cloudflare.com", "/generate_204", (204,)),
    TestEndpoint("www.gstatic.com", "/generate_204", (204,)),
    TestEndpoint("captive.apple.com", "/hotspot-detect.html", (200,)),
)
ENDPOINT_CHECK_TIMEOUT = 10.0
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

ROUNDS = 3                 # a node must pass every round
REQUEST_TIMEOUT = 5.0      # seconds, matches upstream's 5000ms budget
BATCH_SIZE = 96            # nodes per Xray process
PROBE_WORKERS = 32         # concurrent probes within a batch
PORT_RESERVE_ATTEMPTS = 3
STARTUP_TIMEOUT = 15.0     # seconds to wait for Xray to bind its inbounds
SHUTDOWN_TIMEOUT = 5.0
PAUSE_BETWEEN_ROUNDS = 3.0


class HealthCheckError(RuntimeError):
    pass


def _node_to_outbound(node: Any, tag: str) -> dict:
    """تبدیل منعطف نود (خواه آبجکت Node یا دیکشنری خام) به ساختار Outbound استاندارد Xray"""
    if hasattr(node, "to_outbound"):
        return node.to_outbound(tag)

    if isinstance(node, dict):
        protocol = node.get("protocol", "vless").lower()
        host = node.get("host", "")
        port = int(node.get("port", 443))
        raw_link = node.get("raw", "")
        parsed = urlparse(raw_link)
        query = parse_qs(parsed.query)

        GAPGPTMASKTOKENpoyk4ak93ihX0X = parsed.username or node.get("id", "")
        sni = query.get("sni", [node.get("sni", "")])[0]
        security = query.get("security", [node.get("tls", "none")])[0].lower()
        net = query.get("type", [node.get("network", "tcp")])[0].lower()
        path = query.get("path", [node.get("path", "/")])[0]
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

        if protocol == "vless":
            outbound["settings"] = {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": GAPGPTMASKTOKENpoyk4ak93ihX1X,
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
                        "id": GAPGPTMASKTOKENpoyk4ak93ihX2X,
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
                    "password": GAPGPTMASKTOKENpoyk4ak93ihX3X
                }]
            }
        elif protocol == "shadowsocks":
            method = query.get("method", ["aes-128-gcm"])[0]
            outbound["settings"] = {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": GAPGPTMASKTOKENpoyk4ak93ihX4X
                }]
            }

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
            stream["grpcSettings"] = {
                "serviceName": query.get("serviceName", [""])[0],
                "multiMode": True
            }

        return outbound

    raise ValueError(f"Unsupported node type: {type(node)}")


def _build_config(batch: list[Any], ports: list[int]) -> dict:
    inbounds: list[dict] = []
    # The blackhole is listed first so it is Xray's default outbound: anything
    # not matched by an explicit rule is dropped rather than sent out directly.
    outbounds: list[dict] = [{"tag": "block", "protocol": "blackhole"}]
    rules: list[dict] = []

    for index, node in enumerate(batch):
        in_tag = f"in-{index}"
        out_tag = f"out-{index}"
        inbounds.append(
            {
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": ports[index],
                "protocol": "http",
                "settings": {},
            }
        )
        outbounds.append(_node_to_outbound(node, out_tag))
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "block"})
    return {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }


def _placeholder_ports(count: int) -> list[int]:
    """Port numbers for configs that are only validated, never run."""
    return list(range(21080, 21080 + count))


def reserve_ports(count: int) -> list[int]:
    """Ask the OS for ``count`` free loopback ports."""
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
    raise HealthCheckError(f"could not reserve {count} free ports")


def _write_config(config: dict, directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False)
    return path


def _config_accepted(xray: str, config: dict, directory: str) -> bool:
    """True when Xray parses and builds this config."""
    path = _write_config(config, directory, "validate.json")
    try:
        result = subprocess.run(
            [xray, "run", "-test", "-c", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def validate_nodes(
    xray: str, nodes: list[Any], directory: str
) -> tuple[list[Any], list[Any]]:
    """Split ``nodes`` into those Xray accepts and those it rejects."""
    def group_builds(group: list[Any]) -> bool:
        try:
            config = _build_config(group, _placeholder_ports(len(group)))
        except Exception:
            return False
        return _config_accepted(xray, config, directory)

    def recurse(group: list[Any]) -> tuple[list[Any], list[Any]]:
        if not group:
            return [], []
        if group_builds(group):
            return list(group), []
        if len(group) == 1:
            return [], list(group)
        middle = len(group) // 2
        left_ok, left_bad = recurse(group[:middle])
        right_ok, right_bad = recurse(group[middle:])
        return left_ok + right_ok, left_bad + right_bad

    accepted: list[Any] = []
    rejected: list[Any] = []
    for start in range(0, len(nodes), BATCH_SIZE):
        chunk_ok, chunk_bad = recurse(nodes[start : start + BATCH_SIZE])
        accepted.extend(chunk_ok)
        rejected.extend(chunk_bad)
    return accepted, rejected


def preflight(xray: str) -> list[str]:
    """Check that this core understands everything the emitted links rely on."""
    if transform is None or Node is None:
        return []

    try:
        version = subprocess.run(
            [xray, "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [f"running '{xray} version' failed: {error}"]
    if version.returncode != 0:
        return [f"'{xray} version' exited {version.returncode}"]
    print(f"  core: {version.stdout.decode('utf-8', 'replace').splitlines()[0]}")

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="xray-preflight-") as directory:
        for description, node in preflight_probes():
            if not _config_accepted(xray, _preflight_config(node), directory):
                failures.append(description)
    return failures


def _preflight_config(node: Any) -> dict:
    config = _build_config([node], _placeholder_ports(1))
    if hasattr(node, "ech_outbound"):
        ech_outbound = node.ech_outbound()
        if ech_outbound is not None:
            config["outbounds"].append(ech_outbound)
    return config


def preflight_probes() -> list[tuple[str, Any]]:
    if transform is None or Node is None:
        return []

    def probe(address: str, port: str, **extra: str) -> Any:
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": "example.com",
            "path": "/",
            "sni": "example.com",
        }
        params.update({k: v for k, v in extra.items() if v})
        return Node(
            scheme="vless",
            uid="00000000-0000-0000-0000-000000000000",
            address=address,
            port=str(port),
            params=params,
        )

    probes = [
        (
            "tested shape (plain TLS, none of the variant fields)",
            probe(transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT),
        )
    ]
    total = len(transform.VARIANTS)
    for index, variant in enumerate(transform.VARIANTS):
        carries = ["fm fragment" if variant.fm else "no fm"]
        if variant.dial_mode:
            carries.append(f"dialMode {variant.dial_mode}")
        if variant.ech:
            carries.append("ech")
        if variant.ech_outbound:
            carries.append("echOutbound")
        if variant.fp:
            carries.append(f"fp {variant.fp}")
        if variant.cs:
            carries.append("cs")
        where = f" {index + 1}/{total}" if total > 1 else ""
        probes.append(
            (
                f"published shape{where} ({' + '.join(carries)})",
                probe(
                    transform.OUTPUT_ADDRESS,
                    transform.OUTPUT_PORT,
                    **dict(zip(transform.VARIANT_KEYS, variant)),
                ),
            )
        )
    return probes


def _wait_until_listening(
    ports: list[int], deadline: float, process: subprocess.Popen | None = None
) -> bool:
    for port in ports:
        while True:
            if process is not None and process.poll() is not None:
                return False
            if time.monotonic() > deadline:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.05)
    return True


def _log_tail(path: str, lines: int = 6) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            tail = [l.rstrip() for l in handle if l.strip()][-lines:]
        return "\n".join("      " + l[:200] for l in tail)
    except OSError:
        return "      (no log)"


def usable_endpoints() -> list[TestEndpoint]:
    """Drop endpoints this machine cannot reach directly."""
    usable: list[TestEndpoint] = []
    for endpoint in TEST_ENDPOINTS:
        connection = http.client.HTTPSConnection(
            endpoint.host, 443, timeout=ENDPOINT_CHECK_TIMEOUT
        )
        try:
            connection.request(
                "GET", endpoint.path,
                headers={"User-Agent": USER_AGENT, "Connection": "close"},
            )
            response = connection.getresponse()
            response.read()
            if response.status in endpoint.statuses:
                usable.append(endpoint)
            else:
                print(f"  ! {endpoint.host} answered {response.status}; not testing against it")
        except Exception as error:
            print(f"  ! {endpoint.host} unreachable ({type(error).__name__});"
                  " not testing against it")
        finally:
            try:
                connection.close()
            except Exception:
                pass
    return usable


def _probe(port: int, endpoint: TestEndpoint) -> tuple[bool, float]:
    """Fetch the endpoint through the loopback proxy on ``port``."""
    started = time.monotonic()
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT)
    try:
        connection.set_tunnel(endpoint.host, 443)
        connection.request(
            "GET", endpoint.path, headers={"User-Agent": USER_AGENT, "Connection": "close"}
        )
        response = connection.getresponse()
        response.read()
        elapsed = (time.monotonic() - started) * 1000.0
        return response.status in endpoint.statuses, elapsed
    except Exception:
        return False, (time.monotonic() - started) * 1000.0
    finally:
        try:
            connection.close()
        except Exception:
            pass


def _run_batch(
    xray: str, batch: list[Any], directory: str, label: str, endpoint: TestEndpoint
) -> dict[int, float]:
    """Return ``{index within batch: latency ms}`` for the nodes that passed."""
    if not batch:
        return {}
    try:
        ports = reserve_ports(len(batch))
    except (OSError, HealthCheckError) as error:
        print(f"  ! {label}: could not reserve {len(batch)} ports ({error});"
              f" {len(batch)} nodes not tested this round")
        return {}
    config = _build_config(batch, ports)
    config_path = _write_config(config, directory, f"{label}.json")
    log_path = os.path.join(directory, f"{label}.log")

    with open(log_path, "wb") as log_handle:
        process = subprocess.Popen(
            [xray, "run", "-c", config_path],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + STARTUP_TIMEOUT
            if not _wait_until_listening([ports[0], ports[-1]], deadline, process):
                print(
                    f"  ! {label}: Xray did not start (exit={process.poll()});"
                    f" {len(batch)} nodes not tested this round"
                )
                print(_log_tail(log_path))
                return {}
            with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
                results = list(
                    pool.map(lambda i: _probe(ports[i], endpoint), range(len(batch)))
                )
        finally:
            process.terminate()
            try:
                process.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    return {i: latency for i, (ok, latency) in enumerate(results) if ok}


def check(
    xray: str, nodes: list[Any], stats: dict | None = None, rounds: int = ROUNDS
) -> list[Any]:
    """Return the nodes that passed a real proxied request in every round,
    ordered fastest-first by median latency across the rounds."""
    counts: dict = stats if stats is not None else {}
    if not nodes:
        counts["healthy"] = 0
        return []

    # گیت‌بان شبیه‌ساز فیلترینگ ایران: نودهایی که مشخصاً در ایران فیلتر هستند قبل از هزینه پردازشی حذف می‌شوند
    filtered_nodes: list[Any] = []
    for node in nodes:
        if isinstance(node, dict):
            # اگر دیتای ورودی دیکشنری باشد از چک‌های اولیه عبور می‌کند
            valid = evaluate_node_vitality(node)
            if valid is not None:
                filtered_nodes.append(node)
        elif hasattr(node, "params"):
            # اگر آبجکت Node باشد
            host = getattr(node, "address", "")
            sni = node.params.get("sni", host)
            raw = getattr(node, "to_link", lambda: "")()
            if not is_blocked_in_iran(sni, host):
                if node.params.get("security") == "reality" and not validate_reality_config(raw):
                    continue
                filtered_nodes.append(node)
        else:
            filtered_nodes.append(node)

    print(f"[*] Virtual GFW Filter: {len(filtered_nodes)}/{len(nodes)} survived initial heuristics.")
    nodes = filtered_nodes
    if not nodes:
        counts["healthy"] = 0
        return []

    endpoints = usable_endpoints()
    if not endpoints:
        raise HealthCheckError(
            "no test endpoint is reachable, so nothing can be measured; "
            "leaving the previous list in place"
        )
    counts["endpoints"] = [e.host for e in endpoints]

    with tempfile.TemporaryDirectory(prefix="xray-healthcheck-") as directory:
        accepted, rejected = validate_nodes(xray, nodes, directory)
        counts["rejected_by_xray"] = len(rejected)
        counts["validated"] = len(accepted)
        for node in rejected:
            tag_name = getattr(node, "tag", None) or (node.get("host") if isinstance(node, dict) else str(node))
            print(f"  ! Xray rejected: {tag_name}")
        if not accepted:
            counts["healthy"] = 0
            return []

        latencies: dict[int, list[float]] = {i: [] for i in range(len(accepted))}
        survivors = set(range(len(accepted)))

        for round_number in range(1, rounds + 1):
            endpoint = endpoints[(round_number - 1) % len(endpoints)]
            passed: set[int] = set()
            for start in range(0, len(accepted), BATCH_SIZE):
                batch = accepted[start : start + BATCH_SIZE]
                label = f"r{round_number}-b{start // BATCH_SIZE}"
                batch_result = _run_batch(xray, batch, directory, label, endpoint)
                for offset, latency in batch_result.items():
                    index = start + offset
                    passed.add(index)
                    latencies[index].append(latency)
            counts[f"round_{round_number}_passed"] = len(passed)
            survivors &= passed
            print(
                f"  round {round_number}/{rounds} via {endpoint.host}: "
                f"{len(passed)}/{len(accepted)} passed, {len(survivors)} still perfect"
            )
            if round_number < rounds:
                time.sleep(PAUSE_BETWEEN_ROUNDS)

    ever_passed = sum(1 for values in latencies.values() if values)
    if ever_passed:
        counts["flaky_percent"] = round(
            100.0 * (ever_passed - len(survivors)) / ever_passed, 2
        )
    counts["healthy"] = len(survivors)

    # سیستم امتیازدهی و رتبه‌بندی نهایی هوشمند با لحاظ کردن پایداری پروتکل‌ها در ایران
    def calculate_score(idx: int) -> float:
        med = statistics.median(latencies[idx])
        item = accepted[idx]
        score = med
        if isinstance(item, dict):
            sec = item.get("tls", "").lower()
            proto = item.get("protocol", "").lower()
            if sec == "reality":
                score -= 300
            elif proto == "vless":
                score -= 50
            elif proto == "vmess":
                score += 150
        elif hasattr(item, "params"):
            sec = item.params.get("security", "").lower()
            proto = getattr(item, "scheme", "").lower()
            if sec == "reality":
                score -= 300
            elif proto == "vless":
                score -= 50
            elif proto == "vmess":
                score += 150
        return score

    ordered = sorted(survivors, key=lambda i: (calculate_score(i), statistics.median(latencies[i]), i))
    
    for index in ordered:
        med_lat = round(statistics.median(latencies[index]))
        if isinstance(accepted[index], dict):
            accepted[index]["latency"] = med_lat
            accepted[index]["score"] = calculate_score(index)
        else:
            setattr(accepted[index], "latency_ms", med_lat)
            setattr(accepted[index], "score", calculate_score(index))

    return [accepted[i] for i in ordered]
