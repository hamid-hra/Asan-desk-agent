"""بخش مخصوص سرور راست‌دسک (hbbs/hbbr) در agent آسان‌دسک.

دو کار انجام می‌شود و هیچ‌کدام به سرور دست نمی‌زنند:

1. وضعیت پروسه‌های hbbs/hbbr و مصرف CPU/RAM‌شان (با `--pid host` از /proc خوانده می‌شود؛ بدون docker.sock).
2. فهرست دستگاه‌هایی که تا حالا به سرور شناسه ثبت‌نام کرده‌اند، از دیتابیس خود hbbs (`db_v2.sqlite3`، جدول
   `peer`). پوشهٔ دادهٔ hbbs فقط‌خواندنی mount می‌شود و agent هیچ‌چیز در آن نمی‌نویسد: فایل‌ها به یک پوشهٔ
   موقت کپی می‌شوند و روی کپی خوانده می‌شوند.
"""

import base64
import hashlib
import ipaddress
import json
import logging
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

log = logging.getLogger("agent.hbbs")

DB_NAME = "db_v2.sqlite3"
# -shm عمداً کپی نمی‌شود: SQLite هنگام باز کردن کپی آن را از روی -wal دوباره می‌سازد
COPIED_FILES = (DB_NAME, DB_NAME + "-wal")
WATCHED_FILES = COPIED_FILES + (DB_NAME + "-shm",)
BATCH = 500


# ---------- سرویس‌ها ----------

def collect_services(names, cores: int) -> dict:
    """{name: {up, uptime_s, cpu, ram}} فقط برای پروسه‌هایی که نامشان دقیقاً در `names` است."""
    wanted = set(names)
    found = {n: [] for n in names}
    for proc in psutil.process_iter(["name"]):
        if proc.info.get("name") in wanted:
            found[proc.info["name"]].append(proc)

    out = {}
    now = time.time()
    for name, procs in found.items():
        cpu = ram = 0.0
        uptime = 0
        alive = False
        for p in procs:
            try:
                cpu += p.cpu_percent(None)
                ram += p.memory_info().rss
                uptime = max(uptime, int(now - p.create_time()))
                alive = True
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                alive = True
        out[name] = {
            "up": alive,
            "uptime_s": uptime if alive else 0,
            # نسبت به کل CPU میزبان (cpu_percent هر پروسه تا ۱۰۰ × تعداد هسته است)
            "cpu": round(min(100.0, cpu / max(1, cores)), 2),
            "ram": int(ram),
        }
    return out


# ---------- دستگاه‌های ثبت‌شده در hbbs ----------

def uuid_hash(raw: bytes | None) -> str:
    """sha256 متن base64 دادهٔ uuid؛ همان متنی که کلاینت در heartbeat می‌فرستد و پنل از آن hash می‌گیرد."""
    if not raw:
        return ""
    return hashlib.sha256(base64.b64encode(bytes(raw))).hexdigest()


def normalize_ip(raw) -> str:
    text = str(raw or "").strip()
    if text.count(":") == 1:  # IPv4 همراه پورت
        text = text.split(":")[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_created_at(raw) -> str | None:
    """created_at در SQLite = وقت UTC بدون منطقهٔ زمانی."""
    try:
        return datetime.fromisoformat(str(raw)).replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def peer_ip(info) -> str:
    try:
        data = json.loads(info or "{}")
    except (TypeError, ValueError):
        return ""
    return normalize_ip(data.get("ip")) if isinstance(data, dict) else ""


def read_peers(directory) -> list[dict]:
    """ردیف‌های جدول peer از روی یک کپی از دیتابیس hbbs. اگر کپی ناسازگار بود sqlite3.DatabaseError می‌دهد."""
    src = Path(directory)
    if not (src / DB_NAME).is_file():
        raise FileNotFoundError(src / DB_NAME)
    with tempfile.TemporaryDirectory(prefix="hbbs-") as tmp:
        for name in COPIED_FILES:
            if (src / name).is_file():
                shutil.copyfile(src / name, Path(tmp) / name)
        conn = sqlite3.connect(Path(tmp) / DB_NAME)
        try:
            rows = conn.execute("SELECT id, uuid, info, created_at FROM peer").fetchall()
        finally:
            conn.close()
    peers = []
    for rd_id, uuid, info, created_at in rows:
        if not rd_id:
            continue
        peers.append({
            "id": str(rd_id),
            "uuid_hash": uuid_hash(uuid),
            "ip": peer_ip(info),
            "created_at": parse_created_at(created_at),
        })
    return peers


def fingerprint(directory) -> tuple:
    """(نام، mtime، اندازه) فایل‌های دیتابیس؛ تا عوض نشده لازم نیست دوباره خوانده شود."""
    out = []
    for name in WATCHED_FILES:
        try:
            st = (Path(directory) / name).stat()
        except OSError:
            continue
        out.append((name, st.st_mtime_ns, st.st_size))
    return tuple(out)


class PeersSync:
    """هر `interval` ثانیه دیتابیس hbbs را می‌سنجد و اگر عوض شده بود (یا هر `full_every` ثانیه) کل فهرست را می‌فرستد."""

    def __init__(self, directory, url: str, session, interval: float = 600, full_every: float = 6 * 3600):
        self.directory, self.url, self.session = directory, url, session
        self.interval, self.full_every = interval, full_every
        self._checked = None
        self._sent = None
        self._fp = None

    def maybe_sync(self):
        now = time.monotonic()
        if self._checked is not None and now - self._checked < self.interval:
            return None
        self._checked = now
        fp = fingerprint(self.directory)
        if fp == self._fp and self._sent is not None and now - self._sent < self.full_every:
            return None
        peers = read_peers(self.directory)
        totals = {"created": 0, "updated": 0, "skipped": 0}
        for i in range(0, len(peers), BATCH):
            r = self.session.post(self.url, json={"peers": peers[i:i + BATCH]}, timeout=30)
            r.raise_for_status()
            for key, value in r.json().items():
                if key in totals:
                    totals[key] += int(value)
        self._fp, self._sent = fp, now
        log.info("peers sync: %d peers read, %s", len(peers), totals)
        return {"peers": len(peers), **totals}
