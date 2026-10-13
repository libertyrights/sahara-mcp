"""Hardware-free tests for sahara-mcp.

Two groups:

* guard tests -- the two device-acting tools (``sahara_reset``,
  ``sahara_upload``) must refuse to touch the device unless BOTH
  ``dry_run=False`` AND ``confirm=True`` are passed. The USB opener is
  monkeypatched to raise, so any attempt to open a transport fails the test.
* pure-logic tests -- packet build/parse round-trips against known byte
  layouts, plus the HELLO_RESP layout.

These run deterministically and never need a device or pyusb.
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sahara_mcp_server as s  # noqa: E402


# ---------------------------------------------------------------------------
# Guard tests
# ---------------------------------------------------------------------------


@pytest.fixture
def no_device(monkeypatch):
    """Explode if any guarded dry run tries to open a USB transport."""

    def boom(*args, **kwargs):
        raise AssertionError("USB transport opened during a guarded dry run")

    monkeypatch.setattr(s, "_open", boom)
    monkeypatch.setattr(s, "_with_sahara", boom)
    return boom


def test_reset_defaults_are_dry_run(no_device):
    res = s.sahara_reset()
    assert res["executed"] is False
    assert res["dry_run"] is True
    assert res["would_do"] == {"action": "reset"}
    assert res["message"] == (
        "DRY RUN \u2014 nothing done; set dry_run=False and "
        "confirm=True to proceed."
    )


def test_upload_defaults_are_dry_run(no_device):
    res = s.sahara_upload()
    assert res["executed"] is False
    assert res["dry_run"] is True
    assert res["would_do"]["action"] == "upload"
    assert "DRY RUN" in res["message"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dry_run": True, "confirm": True},
        {"dry_run": False, "confirm": False},
        {"dry_run": True, "confirm": False},
        {"dry_run": False},
        {"confirm": True},
    ],
)
def test_reset_requires_both_flags(no_device, kwargs):
    res = s.sahara_reset(**kwargs)
    assert res["executed"] is False
    assert res["would_do"] == {"action": "reset"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dry_run": True, "confirm": True},
        {"dry_run": False, "confirm": False},
        {"dry_run": True, "confirm": False},
    ],
)
def test_upload_requires_both_flags(no_device, kwargs):
    res = s.sahara_upload(**kwargs)
    assert res["executed"] is False
    assert res["would_do"]["action"] == "upload"


def test_reset_proceeds_only_when_both_flags(monkeypatch):
    seen = {}

    def fake_with_sahara(index, fn):
        seen["index"] = index
        return "ok"

    monkeypatch.setattr(s, "_with_sahara", fake_with_sahara)
    res = s.sahara_reset(dry_run=False, confirm=True)
    assert res == {"status": "reset issued"}
    assert seen["index"] == 0


def test_upload_proceeds_only_when_both_flags(monkeypatch, tmp_path):
    img = tmp_path / "prog_firehose.elf"
    img.write_bytes(b"\x7fELF" + b"\x00" * 28)
    seen = {}

    def fake_with_sahara(index, fn):
        seen["entered"] = True
        return {"done": True, "served_bytes": {"0": img.stat().st_size}}

    monkeypatch.setattr(s, "_with_sahara", fake_with_sahara)
    res = s.sahara_upload(images=f"0:{img}", dry_run=False, confirm=True)
    assert seen.get("entered") is True
    assert res["done"] is True


def test_upload_missing_file_without_guard_is_reported(monkeypatch, tmp_path):
    """Once armed, a bad image spec is a clean error -- never a crash."""
    def should_not_open(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("device opened before validating the image spec")

    monkeypatch.setattr(s, "_with_sahara", should_not_open)
    res = s.sahara_upload(
        images=f"0:{tmp_path / 'missing.elf'}", dry_run=False, confirm=True
    )
    assert "error" in res


# ---------------------------------------------------------------------------
# Pure-logic packet tests
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Minimal read-side transport used to exercise recv_packet."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read_exact(self, length: int, timeout_ms=None) -> bytes:
        chunk = self._data[self._pos:self._pos + length]
        if len(chunk) != length:
            raise s.SaharaError(f"short read: wanted {length}, got {len(chunk)}")
        self._pos += length
        return chunk

    def write(self, data: bytes, timeout_ms=None) -> int:
        return len(data)

    def close(self) -> None:
        pass


def test_build_packet_header_and_payload():
    pkt = s.build_packet(s.SAHARA_HELLO_RESP_CMD, b"\xAA\xBB")
    cmd, length = struct.unpack_from("<II", pkt, 0)
    assert cmd == 0x02
    assert length == 8 + 2
    assert len(pkt) == 10
    assert pkt[8:] == b"\xAA\xBB"


def test_hello_round_trip():
    payload = struct.pack(
        "<IIII", 2, 1, 0x1000, s.SAHARA_MODE_COMMAND
    ) + b"\x00" * 8
    pkt = s.SaharaPacket(s.SAHARA_HELLO_CMD, 8 + len(payload), payload)
    assert pkt.hello() == {
        "version": 2,
        "compatible": 1,
        "max_length": 0x1000,
        "mode": s.SAHARA_MODE_COMMAND,
    }


def test_read_data_round_trip():
    payload = struct.pack("<III", 7, 0x100, 0x200)
    pkt = s.SaharaPacket(s.SAHARA_READ_DATA_CMD, 8 + len(payload), payload)
    assert pkt.read_data() == (7, 0x100, 0x200)


def test_read_data64_round_trip():
    payload = struct.pack("<QQQ", 0x1_0000_0000, 0xABC, 0x1234)
    pkt = s.SaharaPacket(s.SAHARA_READ_DATA64_CMD, 8 + len(payload), payload)
    assert pkt.read_data64() == (0x1_0000_0000, 0xABC, 0x1234)


def test_end_of_image_round_trip():
    payload = struct.pack("<II", 3, 0)
    pkt = s.SaharaPacket(s.SAHARA_END_OF_IMAGE_CMD, 8 + len(payload), payload)
    assert pkt.end_of_image() == (3, 0)


def test_done_status_round_trip():
    payload = struct.pack("<I", 1)
    pkt = s.SaharaPacket(s.SAHARA_DONE_RESP_CMD, 8 + len(payload), payload)
    assert pkt.done_status() == 1


def test_exec_resp_round_trip():
    payload = struct.pack("<II", s.SAHARA_EXEC_CMD_SERIAL_NUM_READ, 4)
    pkt = s.SaharaPacket(s.SAHARA_EXECUTE_RESP_CMD, 8 + len(payload), payload)
    assert pkt.exec_resp() == (s.SAHARA_EXEC_CMD_SERIAL_NUM_READ, 4)


def test_build_then_parse_hello_over_fake_transport():
    payload = struct.pack(
        "<IIII", 2, 1, 0x1000, s.SAHARA_MODE_IMAGE_TX_PENDING
    ) + b"\x00" * 8
    wire = s.build_packet(s.SAHARA_HELLO_CMD, payload)
    pkt = s.Sahara(_FakeTransport(wire)).recv_packet()
    assert pkt.cmd == s.SAHARA_HELLO_CMD
    assert pkt.length == 8 + len(payload)
    assert pkt.hello()["mode"] == s.SAHARA_MODE_IMAGE_TX_PENDING


def test_build_hello_resp_layout():
    wire = s.build_hello_resp(2, s.SAHARA_MODE_COMMAND)
    cmd, length = struct.unpack_from("<II", wire, 0)
    assert cmd == s.SAHARA_HELLO_RESP_CMD
    assert length == 0x30
    assert len(wire) == 0x30
    version, compatible, status, mode = struct.unpack_from("<IIII", wire, 8)
    assert (version, compatible, status, mode) == (
        2, 1, 0, s.SAHARA_MODE_COMMAND
    )
    assert wire[8 + 16:] == b"\x00" * 24


def test_packet_parsers_reject_short_data():
    short = s.SaharaPacket(s.SAHARA_HELLO_CMD, 8, b"")
    with pytest.raises(s.SaharaError):
        short.hello()
    with pytest.raises(s.SaharaError):
        short.read_data()
    with pytest.raises(s.SaharaError):
        short.read_data64()
    with pytest.raises(s.SaharaError):
        short.end_of_image()
    with pytest.raises(s.SaharaError):
        short.done_status()
    with pytest.raises(s.SaharaError):
        short.exec_resp()
