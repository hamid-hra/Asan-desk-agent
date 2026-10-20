"""لاگ کانتینرهای hbbs/hbbr برای «لاگ داکر» پنل؛ فقط خواندنی و بدون docker.sock.

داکر (درایور پیش‌فرض json-file) لاگ هر کانتینر را در `<docker-root>/containers/<id>/<id>-json.log` می‌نویسد.
ایجنت شناسهٔ کانتینر را از `/proc/<pid>/cgroup` پروسهٔ hbbs/hbbr پیدا می‌کند و فقط انتهای همان فایل را از مسیر
فقط‌خواندنیِ `/hostfs` می‌خواند. به hbbs، hbbr یا خود داکر دست نمی‌زند. اگر درایور لاگ چیز دیگری باشد (journald،
local و …) فایل پیدا نمی‌شود و فقط علتش گزارش می‌شود.
"""

import json
import logging
import os
import re

import psutil

log = logging.getLogger("agent.logs")

CONTAINER_ID_RE = re.compile(r"(?:docker[-/]|/)([0-9a-f]{64})(?:\.scope)?")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
FIRST_TAIL = 64 * 1024   # بار اول فقط این‌قدر از انتهای فایل (حدود چند صد خط آخر)
MAX_READ = 256 * 1024    # در هر دور حداکثر این‌قدر خوانده می‌شود
MAX_LINES = 500          # در هر دور برای هر سرویس حداکثر این‌قدر خط فرستاده می‌شود
MAX_TEXT = 2000


def container_id(pid: int, proc: str = "/proc") -> str | None:
    try:
        with open(os.path.join(proc, str(pid), "cgroup")) as f:
            text = f.read()
    except OSError:
        return None
    m = CONTAINER_ID_RE.search(text)
    return m.group(1) if m else None


def container_name(root: str, cid: str) -> str:
    try:
        with open(os.path.join(root, "containers", cid, "config.v2.json")) as f:
            return str(json.load(f).get("Name", "")).lstrip("/")[:64]
    except (OSError, ValueError, AttributeError):
        return cid[:12]


def parse_line(raw: bytes) -> dict | None:
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    text = ANSI_RE.sub("", str(data.get("log", ""))).rstrip("\r\n")
    return {
        "ts": str(data.get("time", ""))[:40],
        "stream": "err" if data.get("stream") == "stderr" else "out",
        "text": text[:MAX_TEXT],
    }


class ServiceLogs:
    """انتهای لاگ هر سرویس را دنبال می‌کند و در هر دور فقط خط‌های تازه را برمی‌گرداند."""

    def __init__(self, names, docker_root: str, proc: str = "/proc"):
        self.names, self.root, self.proc = list(names), docker_root, proc
        # name → (container id, inode, ابتدای فایل, offset). ابتدای فایل هم سنجیده می‌شود چون inode بعد از چرخش ممکن است دوباره استفاده شود
        self._pos: dict[str, tuple[str, int, bytes, int]] = {}
        self._reported: dict[str, str] = {}  # آخرین خطای گزارش‌شده؛ تا عوض نشود دوباره فرستاده نمی‌شود

    def _pid_of(self, name: str) -> int | None:
        for p in psutil.process_iter(["name"]):
            if p.info.get("name") == name:
                return p.pid
        return None

    def collect(self) -> dict:
        """{name: {container, error, lines}} فقط برای سرویس‌هایی که خط تازه یا خطای تازه دارند."""
        out = {}
        for name in self.names:
            item = self._collect_one(name)
            if item is None:
                continue
            if item["lines"] or item["error"] != self._reported.get(name, None):
                self._reported[name] = item["error"]
                out[name] = item
        return out

    def _collect_one(self, name: str) -> dict | None:
        pid = self._pid_of(name)
        if pid is None:
            return None  # پروسه نیست؛ وضعیتش را گزارش سرویس‌ها می‌دهد
        cid = container_id(pid, self.proc)
        if not cid:
            return {"container": "", "error": "این پروسه داخل کانتینر داکر نیست یا شناسهٔ کانتینر پیدا نشد", "lines": []}
        path = os.path.join(self.root, "containers", cid, f"{cid}-json.log")
        try:
            st = os.stat(path)
        except OSError:
            return {"container": container_name(self.root, cid), "error": "فایل لاگ پیدا نشد (درایور لاگ داکر json-file نیست یا AGENT_DOCKER_ROOT درست نیست)", "lines": []}
        try:
            with open(path, "rb") as f:
                head = f.read(64)
        except OSError as exc:
            return {"container": container_name(self.root, cid), "error": f"خواندن فایل لاگ نشد: {exc}", "lines": []}
        prev = self._pos.get(name)
        same_file = bool(prev) and prev[0] == cid and prev[1] == st.st_ino and prev[2] == head[: len(prev[2])]
        if not prev or prev[0] != cid:
            offset = max(0, st.st_size - FIRST_TAIL)  # بار اول یا کانتینر تازه: فقط انتهای فایل
        elif not same_file or prev[3] > st.st_size:
            offset = 0  # فایل چرخیده یا کوتاه شده: فایل تازه از اول
        else:
            offset = prev[3]
        fresh = not prev or prev[0] != cid
        lines, skipped = [], 0
        if st.st_size - offset > 4 * MAX_READ:
            # سیل لاگ (مثلاً بعد از ری‌استارت hbbs): از وسط رد می‌شویم تا عقب نمانیم
            skipped = st.st_size - MAX_READ - offset
            offset = st.st_size - MAX_READ
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                chunk = f.read(MAX_READ)
        except OSError as exc:
            return {"container": container_name(self.root, cid), "error": f"خواندن فایل لاگ نشد: {exc}", "lines": []}
        end = chunk.rfind(b"\n")
        if end < 0:
            self._pos[name] = (cid, st.st_ino, head, offset)
            return {"container": container_name(self.root, cid), "error": "", "lines": []}
        body = chunk[: end + 1]
        if offset and (fresh or skipped):
            body = body[body.find(b"\n") + 1:]  # از وسط فایل شروع کردیم؛ خط اول ممکن است نصفه باشد
        for raw in body.splitlines():
            line = parse_line(raw)
            if line is not None:
                lines.append(line)
        self._pos[name] = (cid, st.st_ino, head, offset + end + 1)
        dropped = max(0, len(lines) - MAX_LINES)
        lines = lines[dropped:]
        if skipped or dropped:
            note = f"… {f'{skipped // 1024} کیلوبایت' if skipped else f'{dropped} خط'} لاگ قبلی فرستاده نشد"
            lines.insert(0, {"ts": lines[0]["ts"] if lines else "", "stream": "meta", "text": note})
        return {"container": container_name(self.root, cid), "error": "", "lines": lines}
