"""sahara-mcp: a Model Context Protocol server for the Qualcomm Sahara protocol.

A native, dependency-light implementation of the Qualcomm Sahara protocol
(the emergency-download boot protocol used by Qualcomm SoCs) exposed to
LLM agents through MCP tools.

The wire format and packet layouts are derived from the publicly documented
protocol facts implemented by ``linux-msm/qdl`` (BSD-3-Clause, Linaro Ltd /
Qualcomm). No GPL code is imported or linked; ``bkerler/edl`` was consulted
only as a behavioural reference.

The server talks to an EDL device over libusb (pyusb). See README for
driver (Zadig/WinUSB) and wiring notes.
"""

from __future__ import annotations

import logging
import os
import struct
import sys
from typing import Dict, List, Optional

logger = logging.getLogger("sahara-mcp")

# ---------------------------------------------------------------------------
# Sahara protocol constants (from the linux-msm/qdl reference implementation)
# ---------------------------------------------------------------------------

SAHARA_HELLO_CMD = 0x01
SAHARA_HELLO_RESP_CMD = 0x02
SAHARA_READ_DATA_CMD = 0x03
SAHARA_END_OF_IMAGE_CMD = 0x04
SAHARA_DONE_CMD = 0x05
SAHARA_DONE_RESP_CMD = 0x06
SAHARA_RESET_CMD = 0x07
SAHARA_RESET_RESP_CMD = 0x08
SAHARA_MEM_DEBUG_CMD = 0x09
SAHARA_MEM_READ_CMD = 0x0A
SAHARA_CMD_READY_CMD = 0x0B
SAHARA_SWITCH_MODE_CMD = 0x0C
SAHARA_EXECUTE_CMD = 0x0D
SAHARA_EXECUTE_RESP_CMD = 0x0E
SAHARA_EXECUTE_DATA_CMD = 0x0F
SAHARA_MEM_DEBUG64_CMD = 0x10
SAHARA_MEM_READ64_CMD = 0x11
SAHARA_READ_DATA64_CMD = 0x12
SAHARA_RESET_STATE_CMD = 0x13
SAHARA_WRITE_DATA_CMD = 0x14

SAHARA_HELLO_LENGTH = 0x30
SAHARA_READ_DATA_LENGTH = 0x14
SAHARA_READ_DATA64_LENGTH = 0x20
SAHARA_END_OF_IMAGE_LENGTH = 0x10
SAHARA_DONE_LENGTH = 0x08
SAHARA_DONE_RESP_LENGTH = 0x0C
SAHARA_RESET_LENGTH = 0x08
SAHARA_EXECUTE_LENGTH = 0x0C
SAHARA_SWITCH_MODE_LENGTH = 0x0C

SAHARA_MODE_IMAGE_TX_PENDING = 0x00
SAHARA_MODE_IMAGE_TX_COMPLETE = 0x01
SAHARA_MODE_MEMORY_DEBUG = 0x02
SAHARA_MODE_COMMAND = 0x03

SAHARA_EXEC_CMD_SERIAL_NUM_READ = 0x01
SAHARA_EXEC_CMD_MSM_HW_ID_READ = 0x02
SAHARA_EXEC_CMD_OEM_PK_HASH_READ = 0x03
SAHARA_EXEC_CMD_READ_CHIP_ID_V3 = 0x0A

EXEC_CMD_NAMES = {
    "serial": SAHARA_EXEC_CMD_SERIAL_NUM_READ,
    "msm_hw_id": SAHARA_EXEC_CMD_MSM_HW_ID_READ,
    "oem_pk_hash": SAHARA_EXEC_CMD_OEM_PK_HASH_READ,
    "chip_id_v3": SAHARA_EXEC_CMD_READ_CHIP_ID_V3,
}

QUALCOMM_VID = 0x05C6
EDL_PRODUCT_IDS = {
    0x9003, 0x9006, 0x9008, 0x900C, 0x900E, 0x900F, 0x9015, 0x9018,
    0x901D, 0x9025, 0x9026, 0x902E, 0x9031, 0x9034, 0x903D, 0x9040,
}

PRODUCT_ID_NAMES = {
    0x9008: "Qualcomm HS-USB QDLoader 9008 (EDL)",
    0x900E: "Qualcomm HS-USB QDLoader 900E (EDL / crash dump)",
    0x900F: "Qualcomm HS-USB QDLoader 900F",
}

MODE_NAMES = {
    SAHARA_MODE_IMAGE_TX_PENDING: "image_tx_pending",
    SAHARA_MODE_IMAGE_TX_COMPLETE: "image_tx_complete",
    SAHARA_MODE_MEMORY_DEBUG: "memory_debug",
    SAHARA_MODE_COMMAND: "command",
}


class SaharaError(Exception):
    """Protocol-level error."""


def build_packet(cmd: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("<II", cmd, length) + payload


def build_hello_resp(version: int, mode: int) -> bytes:
    """HELLO_RESP: {version, compatible=1, status=0, mode} + 24 reserved bytes."""
    payload = struct.pack("<IIII", version, 1, 0, mode) + b"\x00" * 24
    return build_packet(SAHARA_HELLO_RESP_CMD, payload)


class SaharaPacket:
    __slots__ = ("cmd", "length", "data")

    def __init__(self, cmd: int, length: int, data: bytes = b"") -> None:
        self.cmd = cmd
        self.length = length
        self.data = data

    def hello(self) -> Dict[str, int]:
        if len(self.data) < 16:
            raise SaharaError("HELLO packet too short")
        version, compatible, max_len, mode = struct.unpack_from("<IIII", self.data, 0)
        return {
            "version": version,
            "compatible": compatible,
            "max_length": max_len,
            "mode": mode,
        }

    def read_data(self):
        if len(self.data) < 12:
            raise SaharaError("READ_DATA packet too short")
        return struct.unpack_from("<III", self.data, 0)

    def read_data64(self):
        if len(self.data) < 24:
            raise SaharaError("READ_DATA64 packet too short")
        return struct.unpack_from("<QQQ", self.data, 0)

    def end_of_image(self):
        if len(self.data) < 8:
            raise SaharaError("END_OF_IMAGE packet too short")
        return struct.unpack_from("<II", self.data, 0)

    def done_status(self) -> int:
        if len(self.data) < 4:
            raise SaharaError("DONE_RESP packet too short")
        return struct.unpack_from("<I", self.data, 0)[0]

    def exec_resp(self):
        if len(self.data) < 8:
            raise SaharaError("EXECUTE_RESP packet too short")
        return struct.unpack_from("<II", self.data, 0)


# ---------------------------------------------------------------------------
# USB transport (pyusb / libusb)
# ---------------------------------------------------------------------------


class UsbTransport:
    def __init__(self, device, timeout_ms: int = 1000) -> None:
        import usb.core
        import usb.util

        self.usb = usb
        self.device = device
        self.timeout_ms = timeout_ms
        self.ep_in = None
        self.ep_out = None
        self._claimed = False
        self._claim()

    def _claim(self) -> None:
        try:
            if self.device.is_kernel_driver_active(0):
                try:
                    self.device.detach_kernel_driver(0)
                except self.usb.core.USBError:
                    pass
            self.usb.util.claim_interface(self.device, 0)
            self._claimed = True
        except self.usb.core.USBError as exc:
            raise SaharaError(f"failed to claim interface 0: {exc}")

        try:
            config = self.device.get_active_configuration()
        except self.usb.core.USBError:
            try:
                self.device.set_configuration()
                config = self.device.get_active_configuration()
            except self.usb.core.USBError as exc:
                raise SaharaError(f"device has no usable configuration: {exc}")

        intf = config[(0, 0)]
        self.ep_in = self.usb.util.find_descriptor(
            intf,
            custom_match=lambda e: (
                self.usb.util.endpoint_direction(e.bEndpointAddress)
                == self.usb.util.ENDPOINT_IN
                and self.usb.util.endpoint_type(e.bmAttributes)
                == self.usb.util.ENDPOINT_TYPE_BULK
            ),
        )
        self.ep_out = self.usb.util.find_descriptor(
            intf,
            custom_match=lambda e: (
                self.usb.util.endpoint_direction(e.bEndpointAddress)
                == self.usb.util.ENDPOINT_OUT
                and self.usb.util.endpoint_type(e.bmAttributes)
                == self.usb.util.ENDPOINT_TYPE_BULK
            ),
        )
        if self.ep_in is None or self.ep_out is None:
            raise SaharaError("could not locate bulk IN/OUT endpoints")

    def read(self, size: int = 4096, timeout_ms: Optional[int] = None) -> bytes:
        try:
            chunk = self.ep_in.read(size, timeout_ms or self.timeout_ms)
        except self.usb.core.USBTimeoutError:
            raise SaharaError("sahara read timed out")
        except self.usb.core.USBError as exc:
            raise SaharaError(f"sahara read failed: {exc}")
        if isinstance(chunk, int):
            return b""
        return chunk.tobytes() if hasattr(chunk, "tobytes") else bytes(chunk)

    def read_exact(self, length: int, timeout_ms: Optional[int] = None) -> bytes:
        out = bytearray()
        while len(out) < length:
            chunk = self.read(length - len(out), timeout_ms)
            if not chunk:
                break
            out.extend(chunk)
        if len(out) != length:
            raise SaharaError(f"short read: wanted {length}, got {len(out)}")
        return bytes(out)

    def write(self, data: bytes, timeout_ms: Optional[int] = None) -> int:
        total = 0
        while total < len(data):
            n = self.ep_out.write(data[total:], timeout_ms or self.timeout_ms)
            if n is None or n == 0:
                break
            total += n
        return total

    def close(self) -> None:
        if self._claimed:
            try:
                self.usb.util.release_interface(self.device, 0)
            except Exception:
                pass
        try:
            self.usb.util.dispose_resources(self.device)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Sahara protocol client
# ---------------------------------------------------------------------------


class Sahara:
    def __init__(self, transport: UsbTransport) -> None:
        self.t = transport

    # ---- packet helpers ---------------------------------------------------

    def send_packet(self, cmd: int, payload: bytes = b"") -> None:
        pkt = build_packet(cmd, payload)
        if self.t.write(pkt) != len(pkt):
            raise SaharaError(f"short write on command 0x{cmd:X}")

    def recv_packet(self, timeout_ms: Optional[int] = None) -> SaharaPacket:
        header = self.t.read_exact(8, timeout_ms)
        cmd, length = struct.unpack("<II", header)
        data = self.t.read_exact(length - 8, timeout_ms) if length > 8 else b""
        return SaharaPacket(cmd, length, data)

    # ---- HELLO ------------------------------------------------------------

    def recv_hello(self) -> Dict[str, int]:
        pkt = self.recv_packet()
        if pkt.cmd == SAHARA_HELLO_CMD:
            return pkt.hello()
        if pkt.cmd == SAHARA_END_OF_IMAGE_CMD:
            raise SaharaError("device rejected HELLO (END_OF_IMAGE)")
        if pkt.data.startswith(b"<?xml"):
            raise SaharaError("device is already in Firehose mode")
        raise SaharaError(f"unexpected packet 0x{pkt.cmd:X} while waiting for HELLO")

    def send_hello_resp(self, version: int, mode: int) -> None:
        """Reply to the device's HELLO with a HELLO_RESP packet."""
        self.t.write(build_hello_resp(version, mode))

    # ---- command mode -----------------------------------------------------

    def enter_command_mode(self, version: int) -> None:
        self.send_hello_resp(version, SAHARA_MODE_COMMAND)
        pkt = self.recv_packet()
        if pkt.cmd != SAHARA_CMD_READY_CMD:
            raise SaharaError(f"device did not enter command mode (got 0x{pkt.cmd:X})")

    def exec_command(self, client_cmd: int) -> bytes:
        self.send_packet(SAHARA_EXECUTE_CMD, struct.pack("<I", client_cmd))
        pkt = self.recv_packet()
        if pkt.cmd != SAHARA_EXECUTE_RESP_CMD:
            raise SaharaError(f"unexpected reply to exec 0x{client_cmd:X}")
        cmd, data_len = pkt.exec_resp()
        if data_len == 0 or data_len > 4096:
            raise SaharaError(f"exec 0x{client_cmd:X} reported invalid length {data_len}")
        self.send_packet(SAHARA_EXECUTE_DATA_CMD, struct.pack("<I", client_cmd))
        return self.t.read_exact(data_len)

    def switch_mode(self, mode: int) -> None:
        self.send_packet(SAHARA_SWITCH_MODE_CMD, struct.pack("<I", mode))

    def chip_info(self) -> Dict[str, object]:
        # Some QUD targets swallow the first HELLO; if the transport times out
        # we piggy-back an unsolicited HELLO_RESP instead.
        try:
            hello = self.recv_hello()
            version = hello["version"]
        except SaharaError:
            version = 2
            self.send_hello_resp(2, SAHARA_MODE_COMMAND)

        self.enter_command_mode(version)

        result: Dict[str, object] = {"sahara_version": version}
        try:
            raw = self.exec_command(SAHARA_EXEC_CMD_SERIAL_NUM_READ)
            if len(raw) >= 4:
                result["serial"] = hex(struct.unpack_from("<I", raw, 0)[0])
        except SaharaError:
            logger.debug("serial read failed", exc_info=True)

        if version < 3:
            try:
                raw = self.exec_command(SAHARA_EXEC_CMD_MSM_HW_ID_READ)
                if len(raw) >= 8:
                    hwid = struct.unpack_from("<Q", raw, 0)[0]
                    result["hw_id"] = hex(hwid)
                    result["msm_id"] = hex(hwid >> 32)
                    result["oem_id"] = hex((hwid >> 16) & 0xFFFF)
                    result["model_id"] = hex(hwid & 0xFFFF)
            except SaharaError:
                logger.debug("hw id read failed", exc_info=True)
        else:
            try:
                raw = self.exec_command(SAHARA_EXEC_CMD_READ_CHIP_ID_V3)
                if len(raw) >= 44:
                    msm_id = struct.unpack_from("<I", raw, 36)[0]
                    oem_id = struct.unpack_from("<H", raw, 40)[0]
                    model_id = struct.unpack_from("<H", raw, 42)[0]
                    if oem_id == 0 and len(raw) >= 46:
                        oem_id = struct.unpack_from("<H", raw, 44)[0]
                    result["msm_id"] = hex(msm_id)
                    result["oem_id"] = hex(oem_id)
                    result["model_id"] = hex(model_id)
                    result["hw_id"] = hex((msm_id << 32) | (oem_id << 16) | model_id)
            except SaharaError:
                logger.debug("chip id v3 read failed", exc_info=True)

        try:
            raw = self.exec_command(SAHARA_EXEC_CMD_OEM_PK_HASH_READ)
            if raw:
                result["oem_pk_hash"] = raw.hex()
        except SaharaError:
            logger.debug("oem pk hash read failed", exc_info=True)

        # Return the device to image-transfer mode so it re-issues HELLO and
        # stays usable for a subsequent upload without a reset.
        self.switch_mode(SAHARA_MODE_IMAGE_TX_PENDING)
        return result

    # ---- image transfer ---------------------------------------------------

    def upload(self, images: Dict[int, bytes]) -> Dict[str, object]:
        done = False
        served: Dict[str, int] = {}

        # Consume the initial HELLO and echo the device's requested mode.
        hello = self.recv_hello()
        self.send_hello_resp(hello["version"], hello["mode"])

        while not done:
            pkt = self.recv_packet()

            if pkt.cmd == SAHARA_READ_DATA_CMD:
                image, offset, length = pkt.read_data()
                blob = images.get(image)
                if blob is None:
                    raise SaharaError(f"device requested unknown image {image}")
                if offset > len(blob) or length > len(blob) - offset:
                    raise SaharaError(f"invalid range for image {image}")
                n = self.t.write(blob[offset : offset + length])
                if n != length:
                    raise SaharaError(f"short write serving image {image}")
                served[str(image)] = served.get(str(image), 0) + length

            elif pkt.cmd == SAHARA_READ_DATA64_CMD:
                image, offset, length = pkt.read_data64()
                blob = images.get(image)
                if blob is None:
                    raise SaharaError(f"device requested unknown image {image}")
                if offset > len(blob) or length > len(blob) - offset:
                    raise SaharaError(f"invalid range for image {image}")
                n = self.t.write(blob[offset : offset + length])
                if n != length:
                    raise SaharaError(f"short write serving image {image}")
                served[str(image)] = served.get(str(image), 0) + length

            elif pkt.cmd == SAHARA_END_OF_IMAGE_CMD:
                image, status = pkt.end_of_image()
                if status != 0:
                    raise SaharaError(f"end-of-image status {status} for image {image}")
                # Acknowledge and ask the device to proceed / confirm DONE.
                self.send_packet(SAHARA_DONE_CMD)

            elif pkt.cmd == SAHARA_DONE_RESP_CMD:
                status = pkt.done_status()
                # 0 == PENDING (more images expected), 1 == COMPLETE.
                # Some devices (e.g. MSM8916 EDL) report done=0 for a lone
                # image-0 transfer; treat that as complete.
                done = status == 1 or list(images) == [0]

            elif pkt.cmd == SAHARA_RESET_RESP_CMD:
                done = True

            else:
                raise SaharaError(f"unhandled Sahara packet 0x{pkt.cmd:X}")

        return {"done": True, "served_bytes": served}

    def reset(self) -> None:
        try:
            hello = self.recv_hello()
            if hello["mode"] == SAHARA_MODE_MEMORY_DEBUG:
                self.send_hello_resp(hello["version"], SAHARA_MODE_MEMORY_DEBUG)
            else:
                self.send_hello_resp(hello["version"], SAHARA_MODE_COMMAND)
                try:
                    self.recv_packet()  # CMD_READY
                except SaharaError:
                    pass
        except SaharaError:
            self.send_hello_resp(2, SAHARA_MODE_COMMAND)

        for _ in range(5):
            self.send_packet(SAHARA_RESET_CMD)
            try:
                pkt = self.recv_packet()
            except SaharaError:
                # Transport error => the device has generally gone down.
                return
            if pkt.cmd == SAHARA_RESET_RESP_CMD:
                break
            if pkt.cmd == SAHARA_END_OF_IMAGE_CMD:
                raise SaharaError("device rejected reset request")

        # Verify the device actually went down: the next read should time out.
        try:
            self.t.read(4096, timeout_ms=3000)
        except SaharaError:
            return
        raise SaharaError("device acknowledged reset but did not go down")


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None


def _list_devices() -> List[dict]:
    import usb.core

    found = usb.core.find(idVendor=QUALCOMM_VID, find_all=True)
    out = []
    for dev in found or []:
        pid = dev.idProduct
        if pid not in EDL_PRODUCT_IDS and pid not in PRODUCT_ID_NAMES:
            continue
        try:
            sn = usb.core.util.get_string(dev, dev.iSerialNumber)
        except Exception:
            sn = None
        out.append({
            "vid": f"0x{dev.idVendor:04X}",
            "pid": f"0x{pid:04X}",
            "name": PRODUCT_ID_NAMES.get(pid, "Qualcomm EDL device"),
            "bus": dev.bus,
            "address": dev.address,
            "serial": sn,
        })
    return out


def _require() -> None:
    try:
        import usb.core  # noqa: F401
    except ImportError:
        raise SaharaError(
            "pyusb is not installed. Run `pip install pyusb` and make a "
            "libusb backend available (see README)."
        )
    if FastMCP is None:
        raise SystemExit("mcp SDK not installed. Run `pip install -e .`.")


def _open(index: int = 0) -> Sahara:
    import usb.core

    _require()
    found = _list_devices()
    if not found:
        raise SaharaError(
            "no Qualcomm EDL device found. Boot the device into EDL mode and "
            "bind the driver via Zadig/WinUSB (see README)."
        )
    if index < 0 or index >= len(found):
        raise SaharaError(f"device index {index} out of range ({len(found)} found)")
    meta = found[index]
    dev = usb.core.find(
        idVendor=QUALCOMM_VID, idProduct=int(meta["pid"], 16)
    )
    if dev is None:
        raise SaharaError(f"could not reopen device at index {index}")
    return Sahara(UsbTransport(dev))


def _with_sahara(index: int, fn):
    s = _open(index)
    try:
        return fn(s)
    finally:
        s.t.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    if FastMCP is None:
        sys.stderr.write(
            "mcp SDK not installed. Run `pip install -e .`.\n"
        )
        sys.exit(1)

    mcp = FastMCP("sahara-mcp")

    @mcp.tool()
    def sahara_list_devices() -> list:
        """List Qualcomm EDL devices currently visible over USB."""
        try:
            _require()
            return _list_devices()
        except SaharaError as exc:
            return [{"error": str(exc)}]

    @mcp.tool()
    def sahara_handshake(index: int = 0) -> dict:
        """Perform the Sahara HELLO exchange and report the device mode."""
        try:
            def do(s: Sahara):
                h = s.recv_hello()
                s.send_hello_resp(h["version"], h["mode"])
                return {
                    "version": h["version"],
                    "compatible": h["compatible"],
                    "max_length": h["max_length"],
                    "mode": MODE_NAMES.get(h["mode"], h["mode"]),
                }
            return _with_sahara(index, do)
        except SaharaError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def sahara_chipinfo(index: int = 0) -> dict:
        """Identify the EDL device's SoC (serial, HW/chip id, PK hash)."""
        try:
            return _with_sahara(index, lambda s: s.chip_info())
        except SaharaError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def sahara_upload(index: int = 0, images: str = "0:prog_firehose.elf") -> dict:
        """Enter Sahara image-transfer mode and serve one or more images.

        `images` is a comma-separated list of `id:path` pairs. Most commonly
        a single Firehose programmer as image id 0:
        `0:C:\\path\\prog_firehose_ddr.elf`
        """
        try:
            image_map: Dict[int, bytes] = {}
            report: Dict[str, object] = {}
            for item in (p.strip() for p in images.split(",") if p.strip()):
                if ":" not in item:
                    raise SaharaError(f"image spec {item!r} must be id:path")
                image_id_s, path = item.split(":", 1)
                image_id = int(image_id_s, 0)
                if not os.path.isfile(path):
                    raise SaharaError(f"image file not found: {path}")
                with open(path, "rb") as fh:
                    blob = fh.read()
                image_map[image_id] = blob
                report[str(image_id)] = {"path": path, "size": len(blob)}

            def do(s: Sahara):
                res = s.upload(image_map)
                report.update(res)
                return report

            return _with_sahara(index, do)
        except SaharaError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def sahara_execute(index: int = 0, command: str = "msm_hw_id") -> dict:
        """Run a single Sahara command-mode client command.

        `command` may be: serial, msm_hw_id, oem_pk_hash, chip_id_v3, or a
        raw number (e.g. 0x0A).
        """
        try:
            if command.lower() in EXEC_CMD_NAMES:
                client_cmd = EXEC_CMD_NAMES[command.lower()]
            else:
                client_cmd = int(command, 0)

            def do(s: Sahara):
                hello = s.recv_hello()
                s.enter_command_mode(hello["version"])
                raw = s.exec_command(client_cmd)
                return {
                    "result": raw.hex(),
                    "length": len(raw),
                }

            return _with_sahara(index, do)
        except SaharaError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def sahara_reset(index: int = 0) -> dict:
        """Reset an EDL device over the Sahara protocol."""
        try:
            _with_sahara(index, lambda s: s.reset())
            return {"status": "reset issued"}
        except SaharaError as exc:
            return {"error": str(exc)}

    mcp.run()


if __name__ == "__main__":
    main()