# sahara-mcp

A **native** Python [MCP](https://modelcontextprotocol.io) server for the
**Qualcomm Sahara protocol** — the emergency-download boot protocol used by
Qualcomm SoCs. It lets LLM agents talk directly to an EDL device over USB:
enumerate devices, handshake, query the SoC identity, upload a Firehose
programmer, run command-mode client commands, and reset the device.

No GPL code. The wire format is implemented from the publicly documented
protocol facts in [`linux-msm/qdl`](https://github.com/linux-msm/qdl)
(BSD-3-Clause). [`bkerler/edl`](https://github.com/bkerler/edl) was consulted
only as a behavioural reference and is not imported, linked, or copied.

> **Use at your own risk.** This talks to your phone's low-level bootloader on
> the EDL (`9008`) interface. Badly placed wires, wrong images, or power loss
> while flashing can brick a device. You have been warned.

## Features

- `sahara_list_devices` — enumerate Qualcomm EDL devices on USB
- `sahara_handshake` — perform the HELLO exchange, report protocol version
  and device mode
- `sahara_chipinfo` — read serial, `msm_id` / `oem_id` / `model_id` (hw id),
  and OEM public-key hash
- `sahara_upload` — serve image(s) (typically a Firehose programmer as image
  id `0`) in Sahara image-transfer mode
- `sahara_execute` — run a single command-mode client command
  (`serial`, `msm_hw_id`, `oem_pk_hash`, `chip_id_v3`, or a raw number)
- `sahara_reset` — reset the device over Sahara

## Requirements

- Python 3.8+
- Windows/macOS/Linux with access to the device's EDL USB interface
- A libusb backend for [pyusb](https://github.com/pyusb/pyusb)

### Windows driver note

The EDL interface must use **WinUSB** (via libusb), *not* the default
Qualcomm driver. Use [Zadig](https://zadig.akeo.ie/) to replace the driver on
the `05C6`/`9008` device before pointing pyusb at it.

## Install

```bash
pip install -e .
```

This pulls in `mcp`, `pyusb`, and (on Windows) `libusb` wheels.

## Usage

Start the MCP server and point an MCP client (e.g. opencode, Claude Desktop)
at it:

```bash
python -m sahara_mcp_server      # stdio transport
```

Example tool call — upload a Firehose programmer and identify the SoC:

```
sahara_upload(index=0, images="0:C:\\firmware\\prog_firehose_ddr.elf")
sahara_chipinfo(index=0)
```

## How it works

The Sahara protocol is a simple request/response stream over one bulk IN and
one bulk OUT endpoint. On entry the device sends a `HELLO`; the host replies
with `HELLO_RESP` choosing a mode (`IMAGE_TX_PENDING` for image transfers,
`COMMAND` for client commands). This package implements the packet framing,
the known command ids (`READ_DATA`, `READ_DATA64`, `END_OF_IMAGE`, `DONE`,
`SWITCH_MODE`, `EXECUTE`, `RESET`, …), and the well-known quirks
(MSM8916 EDL reporting an incomplete `DONE`, QUD devices that swallow the
first `HELLO`).

## Protocol reference

- [`linux-msm/qdl`](https://github.com/linux-msm/qdl) — `src/sahara.c`
  (BSD-3-Clause) — **primary protocol reference**, credited per its license.
- [`bkerler/edl`](https://github.com/bkerler/edl) (GPL-3.0) — consulted for
  behaviour; **not** imported. If you need a full-featured flashing tool,
  consider using it directly instead.

## License

[MIT](LICENSE). Protocol facts derived from `linux-msm/qdl`
(BSD-3-Clause, Linaro Ltd / Qualcomm referents in that project's headers);
all code here is original.