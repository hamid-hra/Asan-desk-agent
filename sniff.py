"""شنود اختیاری ثبت‌نام‌های UDP دستگاه‌ها در hbbs، برای دانستن «چه کسی الان آنلاین است».

hbbs وضعیت آنلاین را فقط در حافظهٔ خودش نگه می‌دارد. هر دستگاه روشن، هر ~۱۲ ثانیه یک بستهٔ UDP ساده
(RegisterPeer، شامل شناسه‌اش) به پورت 21116 می‌فرستد. این ماژول آن بسته‌ها را از روی کارت شبکهٔ میزبان می‌خواند و
فقط شناسه را نگه می‌دارد؛ هیچ بستهٔ دیگری ذخیره یا پردازش نمی‌شود و به سرور چیزی فرستاده نمی‌شود.

نیاز: کانتینر ایجنت با `network_mode: host` و `cap_add: NET_RAW` اجرا شود (فقط کانتینر ایجنت؛ hbbs/hbbr و کانتینرهای دیگر
تغییری نمی‌کنند). بدون آن این حالت خاموش می‌ماند. دستگاهی که مجبور است با TCP ثبت‌نام کند (UDP بسته است) رمزنگاری‌شده
ثبت‌نام می‌کند و از این راه دیده نمی‌شود.
"""

import ctypes
import logging
import re
import socket
import struct
import threading
import time

log = logging.getLogger("agent.sniff")

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
SO_ATTACH_FILTER = 26  # linux/socket.h
ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,32}$")

# RendezvousMessage: register_peer = 6 ، register_pk = 15 (هر دو فیلد اولشان شناسه است)
FIELDS_WITH_ID = (6, 15)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("bad varint")


def fields(data: bytes):
    """(شمارهٔ فیلد، نوع سیم، مقدار) فیلدهای یک پیام protobuf؛ مقدار برای نوع length-delimited بایت‌هاست."""
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 2:
            size, pos = read_varint(data, pos)
            value, pos = data[pos:pos + size], pos + size
            if len(value) != size:
                raise ValueError("truncated")
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ValueError("unsupported wire type")
        yield number, wire, value


def peer_id_from_payload(payload: bytes) -> str | None:
    """شناسهٔ دستگاه از بستهٔ UDP ثبت‌نام (RegisterPeer یا RegisterPk)؛ برای هر بستهٔ دیگر None."""
    try:
        for number, wire, inner in fields(payload):
            if number in FIELDS_WITH_ID and wire == 2:
                for n2, w2, value in fields(inner):
                    if n2 == 1 and w2 == 2:
                        text = value.decode("utf-8")
                        return text if ID_RE.match(text) else None
                return None
    except (ValueError, UnicodeDecodeError):
        return None
    return None


def udp_payload(frame: bytes, port: int) -> bytes | None:
    """بستهٔ UDP با مقصد `port` از یک فریم اترنت (IPv4/IPv6، با یا بدون VLAN) یا None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    pos = 14
    while ethertype == ETH_P_8021Q and len(frame) >= pos + 4:
        ethertype = struct.unpack("!H", frame[pos + 2:pos + 4])[0]
        pos += 4
    if ethertype == ETH_P_IP:
        if len(frame) < pos + 20:
            return None
        ihl = (frame[pos] & 0x0F) * 4
        if frame[pos + 9] != 17:  # UDP
            return None
        frag = struct.unpack("!H", frame[pos + 6:pos + 8])[0]
        if frag & 0x1FFF:  # بخش‌های بعدی یک بستهٔ تکه‌شده سرآیند UDP ندارند
            return None
        pos += ihl
    elif ethertype == ETH_P_IPV6:
        if len(frame) < pos + 40 or frame[pos + 6] != 17:
            return None
        pos += 40
    else:
        return None
    if len(frame) < pos + 8:
        return None
    dport = struct.unpack("!H", frame[pos + 2:pos + 4])[0]
    return frame[pos + 8:] if dport == port else None


def bpf_program(port: int) -> list[tuple[int, int, int, int]]:
    """فیلتر کلاسیک BPF = `udp dst port <port>` برای فریم اترنت (IPv4 و IPv6)، تا هسته فقط همین بسته‌ها را به پایتون بدهد
    و ترافیک سنگین رله (TCP) هیچ هزینه‌ای نداشته باشد. هر دستور: (code, jt, jf, k)."""
    return [
        (0x28, 0, 0, 12),           # 0  ldh [12]            نوع اترنت
        (0x15, 0, 4, 0x86DD),       # 1  jeq IPv6 → 2 ، وگرنه 6
        (0x30, 0, 0, 20),           # 2  ldb [20]            next header
        (0x15, 0, 11, 17),          # 3  jeq UDP → 4 ، وگرنه رد
        (0x28, 0, 0, 56),           # 4  ldh [56]            پورت مقصد (IPv6)
        (0x15, 8, 9, port),         # 5  jeq port → قبول ، وگرنه رد
        (0x15, 0, 8, 0x0800),       # 6  jeq IPv4 → 7 ، وگرنه رد
        (0x30, 0, 0, 23),           # 7  ldb [23]            پروتکل
        (0x15, 0, 6, 17),           # 8  jeq UDP → 9 ، وگرنه رد
        (0x28, 0, 0, 20),           # 9  ldh [20]            fragment
        (0x45, 4, 0, 0x1FFF),       # 10 jset offset → رد
        (0xB1, 0, 0, 14),           # 11 ldxb 4*([14]&0xf)   طول سرآیند IP
        (0x48, 0, 0, 16),           # 12 ldh [x+16]          پورت مقصد (IPv4)
        (0x15, 0, 1, port),         # 13 jeq port → قبول ، وگرنه رد
        (0x06, 0, 0, 0x40000),      # 14 ret (قبول)
        (0x06, 0, 0, 0),            # 15 ret 0 (رد)
    ]


def attach_filter(sock, port: int) -> bool:
    program = bpf_program(port)
    code = ctypes.create_string_buffer(b"".join(struct.pack("HBBI", *ins) for ins in program))
    fprog = struct.pack("HL", len(program), ctypes.addressof(code))
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        return True
    except OSError as exc:
        log.warning("could not attach the packet filter (%s); every packet will be read in Python (slower)", exc)
        return False


class Sniffer:
    """شنودگر پس‌زمینه: {شناسه: آخرین لحظهٔ دیده‌شدن}. پایان‌دادن با stop()."""

    def __init__(self, port: int = 21116, window: float = 45.0):
        self.port, self.window = port, window
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.packets = 0

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.settimeout(1.0)
            attach_filter(sock, self.port)
        except (AttributeError, PermissionError, OSError) as exc:
            log.error("packet capture is not available (%s): run the agent container with network_mode host and cap NET_RAW", exc)
            return False
        self._thread = threading.Thread(target=self._run, args=(sock,), name="sniffer", daemon=True)
        self._thread.start()
        log.info("listening for hbbs registrations on UDP %s (online window %ss)", self.port, self.window)
        return True

    def stop(self) -> None:
        self._stop.set()

    def _run(self, sock) -> None:
        with sock:
            while not self._stop.is_set():
                try:
                    frame = sock.recv(2048)
                except socket.timeout:
                    continue
                except OSError as exc:
                    log.error("packet capture stopped: %s", exc)
                    return
                payload = udp_payload(frame, self.port)
                if payload is None:
                    continue
                peer_id = peer_id_from_payload(payload)
                if peer_id:
                    self.packets += 1
                    with self._lock:
                        self._seen[peer_id] = time.monotonic()

    def online(self) -> list[str]:
        """شناسه‌هایی که در `window` ثانیهٔ اخیر ثبت‌نام کرده‌اند؛ ردیف‌های کهنه پاک می‌شوند."""
        cutoff = time.monotonic() - self.window
        with self._lock:
            self._seen = {k: t for k, t in self._seen.items() if t >= cutoff}
            return list(self._seen)
