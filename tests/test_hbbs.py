import base64
import hashlib
import os
import sqlite3

import pytest

import hbbs

SCHEMA = """
create table if not exists peer (
    guid blob primary key not null,
    id varchar(100) not null,
    uuid blob not null,
    pk blob not null,
    created_at datetime not null default(current_timestamp),
    user blob,
    status tinyint,
    note varchar(300),
    info text not null
) without rowid;
"""


def make_db(directory, rows, wal=False):
    """دیتابیس ساختگی با همان ساختار hbbs. با wal=True تغییرات در فایل -wal می‌مانند (اتصال باز است)."""
    conn = sqlite3.connect(directory / hbbs.DB_NAME)
    if wal:
        conn.execute("pragma journal_mode=wal")
        conn.execute("pragma wal_autocheckpoint=0")
    conn.executescript(SCHEMA)
    for i, (rd_id, uuid, info, created) in enumerate(rows):
        conn.execute(
            "insert into peer (guid, id, uuid, pk, created_at, info) values (?, ?, ?, ?, ?, ?)",
            (bytes([i]) * 16, rd_id, uuid, b"pk", created, info),
        )
    conn.commit()
    return conn


ROWS = [
    ("482913557", b"machine-uuid-1", '{"ip":"5.6.7.8"}', "2025-03-01 10:20:30"),
    ("111222333", b"machine-uuid-2", '{"ip":"::ffff:1.2.3.4"}', "2025-04-02 00:00:00"),
    ("999000111", b"machine-uuid-3", "{}", "2025-05-03 12:00:00"),
]


def test_read_peers_converts_rows(tmp_path):
    make_db(tmp_path, ROWS).close()
    peers = {p["id"]: p for p in hbbs.read_peers(tmp_path)}
    assert set(peers) == {"482913557", "111222333", "999000111"}
    p = peers["482913557"]
    assert p["ip"] == "5.6.7.8"
    assert p["created_at"] == "2025-03-01T10:20:30+00:00"
    assert peers["111222333"]["ip"] == "1.2.3.4"  # ::ffff: برداشته می‌شود
    assert peers["999000111"]["ip"] == ""


def test_uuid_hash_matches_what_the_panel_computes():
    """کلاینت در heartbeat base64(uuid) می‌فرستد و پنل sha256 همان متن را ذخیره می‌کند (clients.models.sha256)."""
    raw = b"machine-uuid-1"
    sent_by_client = base64.b64encode(raw).decode()
    assert hbbs.uuid_hash(raw) == hashlib.sha256(sent_by_client.encode()).hexdigest()
    assert hbbs.uuid_hash(b"") == hbbs.uuid_hash(None) == ""


def test_reads_wal_database_without_touching_the_source(tmp_path):
    conn = make_db(tmp_path, ROWS, wal=True)  # اتصال بسته نمی‌شود: داده‌ها فقط در -wal هستند
    assert (tmp_path / (hbbs.DB_NAME + "-wal")).stat().st_size > 0
    before = {f.name: (f.stat().st_mtime_ns, f.stat().st_size) for f in tmp_path.iterdir()}
    peers = hbbs.read_peers(tmp_path)
    after = {f.name: (f.stat().st_mtime_ns, f.stat().st_size) for f in tmp_path.iterdir()}
    conn.close()
    assert len(peers) == 3
    assert before == after  # هیچ فایلی در پوشهٔ hbbs تغییر نکرد و فایل تازه‌ای ساخته نشد


def test_missing_database(tmp_path):
    with pytest.raises(FileNotFoundError):
        hbbs.read_peers(tmp_path)


@pytest.mark.parametrize("raw, expected", [
    ("1.2.3.4", "1.2.3.4"), ("1.2.3.4:5555", "1.2.3.4"), ("::ffff:9.9.9.9", "9.9.9.9"),
    ("2001:db8::1", "2001:db8::1"), ("", ""), (None, ""), ("not-an-ip", ""),
])
def test_normalize_ip(raw, expected):
    assert hbbs.normalize_ip(raw) == expected


def test_parse_created_at_handles_garbage():
    assert hbbs.parse_created_at("2025-03-01 10:20:30") == "2025-03-01T10:20:30+00:00"
    assert hbbs.parse_created_at("garbage") is None


# ---------- همگام‌سازی ----------

class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


class FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, url, json, timeout):
        self.posts.append((url, json))
        return FakeResponse({"created": len(json["peers"]), "updated": 0, "skipped": 0})


def test_sync_sends_in_batches_and_then_only_what_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(hbbs, "BATCH", 2)
    make_db(tmp_path, ROWS).close()
    session = FakeSession()
    sync = hbbs.PeersSync(tmp_path, "https://panel/api/agent/peers", session, interval=0)

    result = sync.maybe_sync()
    assert result == {"peers": 3, "sent": 3, "created": 3, "updated": 0, "skipped": 0}
    assert [len(body["peers"]) for _, body in session.posts] == [2, 1]
    assert all(url == "https://panel/api/agent/peers" for url, _ in session.posts)

    assert sync.maybe_sync() is None  # فایل عوض نشده
    assert len(session.posts) == 2

    # یک ردیف تازه و یک ردیف تغییرکرده → فقط همان دو فرستاده می‌شود
    conn = sqlite3.connect(tmp_path / hbbs.DB_NAME)
    conn.execute("insert into peer (guid, id, uuid, pk, info) values (?, ?, ?, ?, ?)",
                 (b"z" * 16, "555666777", b"u", b"pk", '{"ip":"8.8.8.8"}'))
    conn.execute("update peer set info = ? where id = ?", ('{"ip":"9.9.9.9"}', "482913557"))
    conn.commit()
    conn.close()
    os.utime(tmp_path / hbbs.DB_NAME, ns=(1, 2**40))  # mtime مطمئناً فرق کند
    result = sync.maybe_sync()
    assert result["peers"] == 4 and result["sent"] == 2
    sent_ids = {p["id"] for p in session.posts[-1][1]["peers"]}
    assert sent_ids == {"555666777", "482913557"}


def test_full_resend_happens_every_full_every_seconds(tmp_path):
    make_db(tmp_path, ROWS).close()
    session = FakeSession()
    sync = hbbs.PeersSync(tmp_path, "u", session, interval=0, full_every=0)
    assert sync.maybe_sync()["sent"] == 3
    assert sync.maybe_sync()["sent"] == 3  # full_every=0: هر بار کامل


def test_sync_respects_interval(tmp_path):
    make_db(tmp_path, ROWS).close()
    session = FakeSession()
    sync = hbbs.PeersSync(tmp_path, "u", session, interval=3600)
    assert sync.maybe_sync() is not None
    assert sync.maybe_sync() is None


def test_failed_post_is_retried_later(tmp_path):
    make_db(tmp_path, ROWS).close()

    class Boom(FakeSession):
        def post(self, url, json, timeout):
            raise RuntimeError("panel down")

    sync = hbbs.PeersSync(tmp_path, "u", Boom(), interval=0)
    with pytest.raises(RuntimeError):
        sync.maybe_sync()
    sync.session = FakeSession()
    assert sync.maybe_sync()["sent"] == 3  # چون ارسال موفق نبود، چیزی «فرستاده‌شده» ثبت نشده است


# ---------- سرویس‌ها ----------

class FakeProc:
    def __init__(self, name, cpu=0.0, rss=0, age=0):
        self.info = {"name": name}
        self._cpu, self._rss, self._age = cpu, rss, age

    def cpu_percent(self, interval=None):
        return self._cpu

    def memory_info(self):
        return type("M", (), {"rss": self._rss})()

    def create_time(self):
        import time
        return time.time() - self._age


def test_collect_services_reports_only_requested_names(monkeypatch):
    procs = [FakeProc("hbbs", cpu=8.0, rss=30_000_000, age=3600), FakeProc("postgres", cpu=90, rss=10**9),
             FakeProc("nginx", cpu=5, rss=10**8)]
    monkeypatch.setattr(hbbs.psutil, "process_iter", lambda attrs=None: procs)
    out = hbbs.collect_services(["hbbs", "hbbr"], cores=4)
    assert set(out) == {"hbbs", "hbbr"}  # postgres و nginx اصلاً دیده نمی‌شوند
    assert out["hbbs"]["up"] is True and out["hbbs"]["cpu"] == 2.0 and out["hbbs"]["ram"] == 30_000_000
    assert 3590 <= out["hbbs"]["uptime_s"] <= 3610
    assert out["hbbr"] == {"up": False, "uptime_s": 0, "cpu": 0.0, "ram": 0}
