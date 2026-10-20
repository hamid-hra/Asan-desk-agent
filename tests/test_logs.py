import json
import os

import pytest

import logs

CID = "a" * 64


class FakeProc:
    def __init__(self, name, pid):
        self.info, self.pid = {"name": name}, pid


@pytest.fixture
def env(tmp_path, monkeypatch):
    """یک /proc و یک docker-root ساختگی: پروسهٔ hbbs (pid 42) داخل کانتینر CID."""
    proc, root = tmp_path / "proc", tmp_path / "docker"
    (proc / "42").mkdir(parents=True)
    (proc / "42" / "cgroup").write_text(f"0::/system.slice/docker-{CID}.scope\n")
    cdir = root / "containers" / CID
    cdir.mkdir(parents=True)
    (cdir / "config.v2.json").write_text(json.dumps({"Name": "/hbbs"}))
    monkeypatch.setattr(logs.psutil, "process_iter", lambda attrs=None: [FakeProc("hbbs", 42), FakeProc("nginx", 7)])
    return proc, root, cdir / f"{CID}-json.log"


def write(path, *texts, stream="stdout", mode="a"):
    with open(path, mode) as f:
        for t in texts:
            f.write(json.dumps({"log": t + "\n", "stream": stream, "time": "2026-10-20T06:00:00.000000001Z"}) + "\n")


@pytest.mark.parametrize("cgroup", [
    f"0::/system.slice/docker-{CID}.scope", f"12:memory:/docker/{CID}", f"0::/../docker-{CID}.scope",
])
def test_container_id_from_cgroup(tmp_path, cgroup):
    (tmp_path / "1").mkdir()
    (tmp_path / "1" / "cgroup").write_text(cgroup + "\n")
    assert logs.container_id(1, str(tmp_path)) == CID


def test_first_read_then_only_new_lines(env):
    proc, root, path = env
    write(path, "INFO starting", "\x1b[32mINFO\x1b[0m listening on 21116")
    sl = logs.ServiceLogs(["hbbs", "hbbr"], str(root), str(proc))
    out = sl.collect()
    assert set(out) == {"hbbs"}  # hbbr پروسه ندارد و چیزی گزارش نمی‌شود
    assert out["hbbs"]["container"] == "hbbs"
    assert [l["text"] for l in out["hbbs"]["lines"]] == ["INFO starting", "INFO listening on 21116"]  # ANSI حذف شد
    assert sl.collect() == {}  # خط تازه‌ای نیست
    write(path, "WARN something", stream="stderr")
    lines = sl.collect()["hbbs"]["lines"]
    assert lines == [{"ts": "2026-10-20T06:00:00.000000001Z", "stream": "err", "text": "WARN something"}]


def test_partial_last_line_waits_for_the_rest(env):
    proc, root, path = env
    write(path, "one")
    with open(path, "a") as f:
        f.write('{"log":"two\\n","stream":"stdout","time":"t"')  # هنوز تمام نشده
    sl = logs.ServiceLogs(["hbbs"], str(root), str(proc))
    assert [l["text"] for l in sl.collect()["hbbs"]["lines"]] == ["one"]
    with open(path, "a") as f:
        f.write("}\n")
    assert [l["text"] for l in sl.collect()["hbbs"]["lines"]] == ["two"]


def test_rotation_and_truncation(env):
    proc, root, path = env
    write(path, "old")
    sl = logs.ServiceLogs(["hbbs"], str(root), str(proc))
    sl.collect()
    os.remove(path)  # چرخش لاگ: فایل تازه با inode دیگر
    write(path, "new after rotate", mode="w")
    assert [l["text"] for l in sl.collect()["hbbs"]["lines"]] == ["new after rotate"]
    write(path, "x", mode="w")  # همان inode ولی کوتاه‌تر
    assert [l["text"] for l in sl.collect()["hbbs"]["lines"]] == ["x"]


def test_flood_is_skipped_with_a_note_and_capped(env, monkeypatch):
    proc, root, path = env
    write(path, "seed")
    sl = logs.ServiceLogs(["hbbs"], str(root), str(proc))
    sl.collect()
    write(path, *[f"update_pk {i}" for i in range(40000)])  # چند مگابایت پشت سر هم
    lines = sl.collect()["hbbs"]["lines"]
    assert lines[0]["stream"] == "meta" and "فرستاده نشد" in lines[0]["text"]
    assert len(lines) <= logs.MAX_LINES + 1
    assert lines[-1]["text"].startswith("update_pk ")


def test_missing_log_file_is_reported_once(env):
    proc, root, path = env
    sl = logs.ServiceLogs(["hbbs"], str(root), str(proc))
    first = sl.collect()
    assert "json-file" in first["hbbs"]["error"]
    assert sl.collect() == {}  # همان خطا دوباره فرستاده نمی‌شود
