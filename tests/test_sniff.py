import struct

import pytest

import sniff


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field(number: int, payload: bytes) -> bytes:
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def register_peer(rd_id: str, serial: int = 0) -> bytes:
    """RendezvousMessage{register_peer = RegisterPeer{id, serial}} همان‌طور که کلاینت می‌فرستد."""
    inner = field(1, rd_id.encode()) + (varint(2 << 3) + varint(serial) if serial else b"")
    return field(6, inner)


def register_pk(rd_id: str) -> bytes:
    return field(15, field(1, rd_id.encode()) + field(2, b"uuid") + field(3, b"pk"))


def eth_ip_udp(payload: bytes, dport=21116, v6=False, vlan=False, proto=17) -> bytes:
    eth = b"\x00" * 12
    udp = struct.pack("!HHHH", 40000, dport, 8 + len(payload), 0) + payload
    if v6:
        ip = b"\x60\x00\x00\x00" + struct.pack("!HBB", len(udp), proto, 64) + b"\x00" * 32
        ethertype = 0x86DD
    else:
        ip = bytes([0x45, 0]) + struct.pack("!HHHBBH", 20 + len(udp), 0, 0, 64, proto, 0) + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ethertype = 0x0800
    if vlan:
        return eth + struct.pack("!HHH", 0x8100, 5, ethertype) + ip + udp
    return eth + struct.pack("!H", ethertype) + ip + udp


@pytest.mark.parametrize("payload, expected", [
    (register_peer("482913557"), "482913557"),
    (register_peer("482913557", serial=3), "482913557"),
    (register_pk("111222333"), "111222333"),
    (field(8, field(1, b"482913557")), None),  # punch_hole_request: شناسهٔ مقصد است، نه فرستنده
    (b"", None),
    (b"\xff\xff\xff", None),
    (field(6, field(1, b"bad id!")), None),
    (field(6, field(1, b"\xff\xfe\xfd\xfc")), None),
])
def test_peer_id_from_payload(payload, expected):
    assert sniff.peer_id_from_payload(payload) == expected


def test_udp_payload_picks_only_registration_port():
    msg = register_peer("482913557")
    assert sniff.udp_payload(eth_ip_udp(msg), 21116) == msg
    assert sniff.udp_payload(eth_ip_udp(msg, v6=True), 21116) == msg
    assert sniff.udp_payload(eth_ip_udp(msg, vlan=True), 21116) == msg
    assert sniff.udp_payload(eth_ip_udp(msg, dport=53), 21116) is None
    assert sniff.udp_payload(eth_ip_udp(msg, proto=6), 21116) is None  # TCP
    assert sniff.udp_payload(b"short", 21116) is None


def test_online_window_forgets_old_registrations(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(sniff.time, "monotonic", lambda: now[0])
    sn = sniff.Sniffer(window=45)
    sn._seen = {"111111111": 960.0, "222222222": 990.0}
    assert sorted(sn.online()) == ["111111111", "222222222"]  # هر دو در پنجرهٔ ۴۵ ثانیه‌اند
    now[0] = 1010.0
    assert sn.online() == ["222222222"]  # اولی ۵۰ ثانیه پیش بود


def test_bpf_program_shape():
    prog = sniff.bpf_program(21116)
    assert len(prog) == 16 and prog[-1] == (0x06, 0, 0, 0) and prog[-2][3] == 0x40000
    # هر پرش باید داخل برنامه فرود بیاید
    for i, (code, jt, jf, k) in enumerate(prog):
        if code & 0x07 == 0x05:  # BPF_JMP
            assert i + 1 + jt < len(prog) and i + 1 + jf < len(prog), i
    assert [ins[3] for ins in prog if ins[0] == 0x15 and ins[3] == 21116] == [21116, 21116]
