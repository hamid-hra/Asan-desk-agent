"""agent مانیتورینگ آسان‌دسک.

منابع سرور میزبان را هر AGENT_INTERVAL ثانیه به داشبورد گزارش می‌دهد.
داخل داکر با `pid: host` اجرا می‌شود تا شبکه و اتصال‌های TCP میزبان از طریق /proc/1 خوانده شود،
و دیسک میزبان از مسیر mount‌شده (AGENT_DISK_PATH، پیش‌فرض /hostfs) اندازه گرفته می‌شود.

روی سرور راست‌دسک (AGENT_HBBS_DIR) وضعیت hbbs/hbbr و فهرست دستگاه‌های ثبت‌شده در hbbs هم گزارش می‌شود
(hbbs.py). agent فقط می‌خواند و به هیچ سرویس یا کانتینری دست نمی‌زند.
"""

import hashlib
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import psutil
import requests

import hbbs
import sniff

VERSION = "2.1.0"

URL = os.environ.get("AGENT_URL", "http://localhost:8000/api/agent/ingest")
TOKEN = os.environ.get("AGENT_TOKEN", "")
# در docker compose، backend توکن را می‌سازد و از طریق volume مشترک در این فایل قرار می‌دهد
TOKEN_FILE = os.environ.get("AGENT_TOKEN_FILE", "")
INTERVAL = float(os.environ.get("AGENT_INTERVAL", "15"))
PROC = os.environ.get("AGENT_PROC", "/proc")
SYS = os.environ.get("AGENT_SYS", "/sys")
DISK_PATH = os.environ.get("AGENT_DISK_PATH", "/hostfs" if os.path.isdir("/hostfs") else "/")
PORTS = {int(p) for p in os.environ.get("AGENT_PORTS", "").split(",") if p.strip()}
CAPACITY_MBPS = float(os.environ.get("AGENT_NET_CAPACITY_MBPS") or "0")
DEFAULT_CAPACITY_BPS = 1_000_000_000
AGENT_IP = os.environ.get("AGENT_IP", "")
# پوشهٔ دادهٔ hbbs (فقط‌خواندنی mount شود): db_v2.sqlite3 و id_ed25519.pub
HBBS_DIR = os.environ.get("AGENT_HBBS_DIR", "")
# مسیر id_ed25519.pub سرور شناسه (اختیاری): sha256 آن گزارش می‌شود تا پنل بتواند یکسان بودن کلید سرورهای HA را بسنجد
KEY_FILE = os.environ.get("AGENT_KEY_FILE") or (os.path.join(HBBS_DIR, "id_ed25519.pub") if HBBS_DIR else "")
# پروسه‌هایی که وضعیتشان گزارش می‌شود؛ روی سرور راست‌دسک پیش‌فرض hbbs,hbbr و در غیر این صورت هیچ
SERVICES = [n.strip() for n in (os.environ.get("AGENT_SERVICES") or ("hbbs,hbbr" if HBBS_DIR else "")).split(",") if n.strip()]
PEERS_INTERVAL = float(os.environ.get("AGENT_PEERS_INTERVAL", "600"))
PEERS_URL = os.environ.get("AGENT_PEERS_URL") or (URL[: -len("/ingest")] + "/peers" if URL.endswith("/ingest") else "")
# شنود اختیاری ثبت‌نام‌های UDP برای وضعیت آنلاین دستگاه‌های قدیمی (sniff.py)؛ نیاز به network_mode: host و cap NET_RAW
SNIFF = os.environ.get("AGENT_SNIFF", "").strip().lower() in ("1", "true", "yes", "on")
SNIFF_PORT = int(os.environ.get("AGENT_SNIFF_PORT") or "21116")
ONLINE_WINDOW = float(os.environ.get("AGENT_ONLINE_WINDOW") or "45")
ONLINE_URL = os.environ.get("AGENT_ONLINE_URL") or (URL[: -len("/ingest")] + "/online" if URL.endswith("/ingest") else "")
ONLINE_BATCH = 2000
# اندازه‌گیری تأخیر: زمان اتصال TCP به این مقصد (پیش‌فرض: خود داشبورد)
PING_TARGET = os.environ.get("AGENT_PING_TARGET", "")

VIRTUAL_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun", "tap", "wg", "kube")

log = logging.getLogger("agent")


def net_namespace_root() -> str:
    # /proc/1/net متعلق به شبکه میزبان است وقتی کانتینر با pid: host اجرا شود
    host = os.path.join(PROC, "1", "net")
    return host if os.access(os.path.join(host, "dev"), os.R_OK) else os.path.join(PROC, "net")


def physical_ifaces(names):
    return [n for n in names if not n.startswith(VIRTUAL_PREFIXES)]


def read_net_bytes():
    """مجموع بایت‌های دریافتی/ارسالی کارت‌های شبکه فیزیکی."""
    rx = tx = 0
    names = []
    with open(os.path.join(net_namespace_root(), "dev")) as f:
        for line in f.readlines()[2:]:
            name, data = line.split(":", 1)
            name = name.strip()
            if name.startswith(VIRTUAL_PREFIXES):
                continue
            cols = data.split()
            rx += int(cols[0])
            tx += int(cols[8])
            names.append(name)
    return rx, tx, names


def link_capacity_bps(names) -> int:
    if CAPACITY_MBPS > 0:
        return int(CAPACITY_MBPS * 1_000_000)
    total = 0
    for name in names:
        try:
            with open(os.path.join(SYS, "class", "net", name, "speed")) as f:
                speed = int(f.read().strip())
            if speed > 0:
                total += speed * 1_000_000
        except (OSError, ValueError):
            continue
    # سرعت لینک قابل تشخیص نبود (مثلاً کارت مجازی) — فرض ۱ گیگابیت
    return total or DEFAULT_CAPACITY_BPS


def tcp_established() -> int:
    count = 0
    root = net_namespace_root()
    for fname in ("tcp", "tcp6"):
        try:
            with open(os.path.join(root, fname)) as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 4 or cols[3] != "01":  # 01 = ESTABLISHED
                continue
            if PORTS:
                local_port = int(cols[1].rsplit(":", 1)[1], 16)
                if local_port not in PORTS:
                    continue
            count += 1
    return count


def host_hostname() -> str:
    for path in ("/hostfs/etc/hostname",):
        try:
            with open(path) as f:
                name = f.read().strip()
            if name:
                return name
        except OSError:
            pass
    return socket.gethostname()


def measure_latency_ms():
    target = PING_TARGET or URL
    parsed = urlparse(target if "://" in target else f"tcp://{target}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except OSError:
        return None
    return round((time.perf_counter() - start) * 1000, 2)


class Collector:
    def __init__(self):
        self.prev = None
        psutil.cpu_percent(interval=None)  # مقدار اول همیشه ۰ است

    def collect(self) -> dict:
        now = time.monotonic()
        rx, tx, names = read_net_bytes()
        rx_bps = tx_bps = 0
        if self.prev:
            dt = max(0.001, now - self.prev[0])
            rx_bps = max(0, int((rx - self.prev[1]) * 8 / dt))
            tx_bps = max(0, int((tx - self.prev[2]) * 8 / dt))
        self.prev = (now, rx, tx)

        capacity = link_capacity_bps(physical_ifaces(names))
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(DISK_PATH)
        net_pct = (rx_bps + tx_bps) / capacity * 100 if capacity else 0
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "cpu": psutil.cpu_percent(interval=None),
            "ram": round((mem.total - mem.available) / mem.total * 100, 2),
            "ram_used": mem.total - mem.available,
            "ram_total": mem.total,
            "disk": round(disk.used / disk.total * 100, 2) if disk.total else 0,
            "disk_used": disk.used,
            "disk_total": disk.total,
            "net_rx_bps": rx_bps,
            "net_tx_bps": tx_bps,
            "net_pct": round(min(100.0, net_pct), 3),
            "net_capacity_bps": capacity,
            "tcp_established": tcp_established(),
            "load1": round(os.getloadavg()[0], 2),
            "latency_ms": measure_latency_ms(),
            "cores": psutil.cpu_count() or 0,
            "hostname": host_hostname(),
            "ip": AGENT_IP,
            "agent_version": VERSION,
            "pubkey_fp": key_fingerprint(),
        }
        if SERVICES:
            payload["services"] = hbbs.collect_services(SERVICES, payload["cores"])
        return payload


def key_fingerprint() -> str:
    if not KEY_FILE:
        return ""
    try:
        with open(KEY_FILE, "rb") as f:
            return hashlib.sha256(f.read().strip()).hexdigest()
    except OSError:
        return ""


def load_token() -> str:
    if TOKEN:
        return TOKEN
    if not TOKEN_FILE:
        raise SystemExit("AGENT_TOKEN or AGENT_TOKEN_FILE is required")
    while True:  # backend هنگام اولین اجرا فایل را می‌سازد
        try:
            with open(TOKEN_FILE) as f:
                token = f.read().strip()
            if token:
                return token
        except OSError:
            pass
        log.info("waiting for token file %s", TOKEN_FILE)
        time.sleep(5)


def make_sniffer():
    if not SNIFF:
        return None
    if not ONLINE_URL:
        log.warning("AGENT_ONLINE_URL is not set and AGENT_URL does not end in /ingest — online devices will not be reported")
        return None
    sniffer = sniff.Sniffer(SNIFF_PORT, ONLINE_WINDOW)
    return sniffer if sniffer.start() else None


def report_online(session, sniffer) -> None:
    """شناسه‌های دستگاه‌هایی که الان آنلاین‌اند (در دسته‌های ۲۰۰۰تایی). بدون هیچ شناسه هم یک گزارش می‌رود تا پنل بداند شنود زنده است."""
    ids = sniffer.online()
    chunks = [ids[i:i + ONLINE_BATCH] for i in range(0, len(ids), ONLINE_BATCH)] or [[]]
    for chunk in chunks:
        r = session.post(ONLINE_URL, json={"ids": chunk}, timeout=15)
        r.raise_for_status()


def start_peers_worker(peers_sync) -> None:
    """همگام‌سازی دستگاه‌های hbbs در رشتهٔ جدا: اولین بار ده‌ها هزار ردیف می‌فرستد و نباید گزارش منابع را متوقف کند
    (وگرنه پنل سرور را «بدون گزارش» می‌بیند)."""

    def run():
        while True:
            try:
                peers_sync.maybe_sync()
            except Exception as exc:  # دیتابیس هنگام کپی در حال نوشتن بود یا پنل در دسترس نیست؛ دور بعد
                log.warning("peers sync failed: %s", exc)
            time.sleep(30)

    threading.Thread(target=run, name="peers-sync", daemon=True).start()


def make_peers_sync(session):
    if not HBBS_DIR:
        return None
    if not os.path.isfile(os.path.join(HBBS_DIR, hbbs.DB_NAME)):
        log.warning("AGENT_HBBS_DIR=%s has no %s — registered devices will not be reported", HBBS_DIR, hbbs.DB_NAME)
        return None
    if not PEERS_URL:
        log.warning("AGENT_PEERS_URL is not set and AGENT_URL does not end in /ingest — registered devices will not be reported")
        return None
    log.info("reporting hbbs devices from %s → %s every %ss", HBBS_DIR, PEERS_URL, PEERS_INTERVAL)
    # رشتهٔ جدا، نشست جدا (requests.Session بین رشته‌ها مشترک نمی‌شود)
    worker = requests.Session()
    worker.headers.update(session.headers)
    return hbbs.PeersSync(HBBS_DIR, PEERS_URL, worker, interval=PEERS_INTERVAL)


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    token = load_token()
    log.info("asandesk agent %s → %s every %ss (disk=%s, net=%s, services=%s)", VERSION, URL, INTERVAL, DISK_PATH,
             net_namespace_root(), ",".join(SERVICES) or "-")
    collector = Collector()
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    peers_sync = make_peers_sync(session)
    if peers_sync:
        start_peers_worker(peers_sync)
    sniffer = make_sniffer()
    backoff = INTERVAL
    time.sleep(1)
    while True:
        started = time.monotonic()
        try:
            payload = collector.collect()
            r = session.post(URL, json=payload, timeout=10)
            if r.status_code == 401:
                log.error("token rejected by dashboard (401)")
            elif r.status_code >= 400:
                log.warning("ingest failed: %s %s", r.status_code, r.text[:200])
            backoff = INTERVAL
        except Exception as exc:  # شبکه یا داشبورد در دسترس نیست — دوباره تلاش می‌کنیم
            log.warning("report failed: %s", exc)
            backoff = min(backoff * 2, 300)
        if sniffer:
            try:
                report_online(session, sniffer)
            except Exception as exc:  # پنل در دسترس نیست؛ دور بعد
                log.warning("online report failed: %s", exc)
        time.sleep(max(1.0, backoff - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
