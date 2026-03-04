#!/usr/bin/env python3
"""Query DTC services, scan Mode 01 PIDs, then poll supported PIDs by JSON rates.

Assumptions/limits:
- Uses 11-bit CAN OBD requests/responses only.
- Uses ISO-TP reassembly for DTC services (03/07/0A), but Mode 01 polling remains
  single-frame.
- Accepts the first matching positive response from configured response IDs.
- DTC query covers services 0x03 (stored), 0x07 (pending), and 0x0A (permanent).
"""

import argparse
import json
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from carbus.can.SocketCAN import CANFilter, SocketCAN


MODE_CURRENT_DATA = 0x01
POSITIVE_RESPONSE_BASE = 0x40
DTC_SERVICES = (
    (0x03, "stored"),
    (0x07, "pending"),
    (0x0A, "permanent"),
)


def parse_can_id(raw: str) -> int:
    return int(raw, 0)


def parse_pid_hex(raw: str) -> int:
    return int(raw, 16)


def mk_obd_request(mode: int, pid: int) -> bytes:
    # Single-frame OBD-II request payload on 11-bit CAN.
    return bytes([0x02, mode & 0xFF, pid & 0xFF, 0, 0, 0, 0, 0])


def mk_obd_service_request(mode: int) -> bytes:
    # Single-frame OBD-II request for service-only modes (ex: 03/07/0A).
    return bytes([0x01, mode & 0xFF, 0, 0, 0, 0, 0, 0])


def mk_isotp_flow_control() -> bytes:
    # Continue To Send, no block size limit, no STmin constraint.
    return bytes([0x30, 0x00, 0x00, 0, 0, 0, 0, 0])


def decode_supported_mask(payload: bytes, mode: int, base_pid: int) -> Optional[int]:
    # Typical response: [len, mode+0x40, pid, A, B, C, D, ...]
    if len(payload) < 7:
        return None
    if payload[1] != (mode + POSITIVE_RESPONSE_BASE) or payload[2] != base_pid:
        return None
    return (payload[3] << 24) | (payload[4] << 16) | (payload[5] << 8) | payload[6]


def extract_pid(payload: bytes, mode: int) -> Optional[int]:
    if len(payload) < 3:
        return None
    if payload[1] != (mode + POSITIVE_RESPONSE_BASE):
        return None
    return payload[2]


def is_positive_service_response(payload: bytes, mode: int) -> bool:
    return len(payload) >= 2 and payload[1] == (mode + POSITIVE_RESPONSE_BASE)


def is_positive_service_payload(payload: bytes, mode: int) -> bool:
    return len(payload) >= 1 and payload[0] == (mode + POSITIVE_RESPONSE_BASE)


def wait_for_response(
    sock: SocketCAN,
    mode: int,
    pid: Optional[int],
    timeout_s: float,
    response_ids: Set[int],
) -> Optional[bytes]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        frame = sock.read()
        if frame.addr not in response_ids:
            continue
        if not is_positive_service_response(frame.data, mode):
            continue
        if pid is not None and extract_pid(frame.data, mode) != pid:
            continue
        return frame.data
    return None


def response_service_data_bytes(payload: bytes, header_len: int) -> bytes:
    # header_len counts bytes after service byte and before data.
    if len(payload) < 2 + header_len:
        return b""
    reported = int(payload[0])
    start = 2 + header_len
    if reported >= (1 + header_len):
        end = min(len(payload), 1 + reported)
        return payload[start:end]
    return payload[start:]


def wait_for_isotp_service_payload(
    sock: SocketCAN,
    mode: int,
    timeout_s: float,
    response_ids: Set[int],
    request_id: int,
) -> Optional[bytes]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        frame = sock.read()
        if frame.addr not in response_ids or len(frame.data) == 0:
            continue

        pci = frame.data[0]
        frame_type = (pci >> 4) & 0xF

        # ISO-TP Single Frame: low nibble is payload length.
        if frame_type == 0x0:
            payload_len = pci & 0xF
            payload = bytes(frame.data[1 : 1 + payload_len])
            if is_positive_service_payload(payload, mode):
                return payload
            continue

        # ISO-TP First Frame: 12-bit payload length across first 2 bytes.
        if frame_type == 0x1 and len(frame.data) >= 2:
            total_len = ((pci & 0xF) << 8) | frame.data[1]
            payload = bytearray(frame.data[2:])
            if len(payload) > total_len:
                payload = payload[:total_len]
            if not payload or not is_positive_service_payload(payload, mode):
                continue

            # Ask ECU to continue with consecutive frames.
            sock.write(mk_isotp_flow_control(), request_id, rtr=False)

            expected_sn = 1
            while len(payload) < total_len and time.monotonic() < deadline:
                cf = sock.read()
                if cf.addr not in response_ids or len(cf.data) == 0:
                    continue
                cf_type = (cf.data[0] >> 4) & 0xF
                if cf_type != 0x2:
                    continue
                sn = cf.data[0] & 0xF
                if sn != expected_sn:
                    continue
                payload.extend(cf.data[1:])
                expected_sn = (expected_sn + 1) & 0xF

            if len(payload) >= total_len:
                return bytes(payload[:total_len])
            return None
    return None


def decode_dtc_code(msb: int, lsb: int) -> Optional[str]:
    if msb == 0 and lsb == 0:
        return None
    type_char = "PCBU"[(msb >> 6) & 0x3]
    first_digit = (msb >> 4) & 0x3
    value = ((msb & 0x3F) << 8) | lsb
    return f"{type_char}{first_digit}{value:03X}"


def decode_dtc_response_service_payload(payload: bytes, mode: int) -> List[str]:
    if not is_positive_service_payload(payload, mode):
        return []
    if len(payload) < 2:
        return []

    # Most ECUs include a DTC count byte after service response (0x43/0x47/0x4A).
    declared_count = int(payload[1])
    dtc_bytes = payload[2:]

    out: List[str] = []
    for i in range(0, len(dtc_bytes) - 1, 2):
        if declared_count > 0 and len(out) >= declared_count:
            break
        code = decode_dtc_code(dtc_bytes[i], dtc_bytes[i + 1])
        if code is not None:
            out.append(code)
    return out


def query_and_print_dtcs(
    sock: SocketCAN,
    request_id: int,
    response_ids: Set[int],
    timeout_s: float,
) -> None:
    print("Querying DTC services before PID polling...")
    for mode, label in DTC_SERVICES:
        sock.write(mk_obd_service_request(mode), request_id, rtr=False)
        payload = wait_for_isotp_service_payload(
            sock=sock,
            mode=mode,
            timeout_s=timeout_s,
            response_ids=response_ids,
            request_id=request_id,
        )
        if payload is None:
            print(f"  {label.title()} DTCs (Mode 0x{mode:02X}): timeout/no response")
            continue
        dtcs = decode_dtc_response_service_payload(payload, mode)
        if dtcs:
            print(f"  {label.title()} DTCs (Mode 0x{mode:02X}): " + ", ".join(dtcs))
        else:
            print(f"  {label.title()} DTCs (Mode 0x{mode:02X}): none")


def scan_supported_mode01_pids(
    sock: SocketCAN,
    request_id: int,
    response_ids: Set[int],
    timeout_s: float,
) -> Set[int]:
    supported: Set[int] = set()
    base = 0x00
    while base <= 0xE0:
        req = mk_obd_request(MODE_CURRENT_DATA, base)
        sock.write(req, request_id, rtr=False)
        data = wait_for_response(sock, MODE_CURRENT_DATA, base, timeout_s, response_ids)
        if data is None:
            break
        mask = decode_supported_mask(data, MODE_CURRENT_DATA, base)
        if mask is None:
            break

        for i in range(32):
            if mask & (1 << (31 - i)):
                supported.add(base + i + 1)

        # Bit for PID base+0x20 indicates whether next block exists.
        if (mask & 0x1) == 0:
            break
        base += 0x20
    return supported


@dataclass
class PollCommand:
    pid: int
    mode: int
    period_s: float
    name: str
    signals: List[Dict]
    next_due: float


def load_mode01_commands(json_path: Path) -> List[Dict]:
    with json_path.open("r", encoding="utf-8") as f:
        doc = json.load(f)

    commands = doc.get("commands", [])
    out: List[Dict] = []
    for cmd in commands:
        mode_pid = cmd.get("cmd", {})
        if "01" not in mode_pid:
            continue
        pid = parse_pid_hex(mode_pid["01"])
        freq = float(cmd.get("freq", 0))
        if freq <= 0:
            continue

        signal_name = ""
        sigs = cmd.get("signals") or []
        if sigs:
            signal_name = str(sigs[0].get("id") or sigs[0].get("name") or "")

        out.append(
            {
                "pid": pid,
                "mode": 0x01,
                "freq": freq,
                "name": signal_name or f"PID_{pid:02X}",
                "signals": sigs,
            }
        )
    return out


def build_poll_plan(
    mode01_commands: Iterable[Dict], supported_mode01: Set[int], now: float
) -> List[PollCommand]:
    plan: List[PollCommand] = []
    for entry in mode01_commands:
        pid = int(entry["pid"])
        if pid not in supported_mode01:
            continue
        period_s = float(entry["freq"])
        if period_s <= 0:
            continue
        plan.append(
            PollCommand(
                pid=pid,
                mode=int(entry["mode"]),
                period_s=period_s,
                name=str(entry["name"]),
                signals=list(entry.get("signals") or []),
                next_due=now,
            )
        )
    plan.sort(key=lambda x: (x.period_s, x.pid))
    return plan


def response_data_bytes(payload: bytes) -> bytes:
    if len(payload) < 4:
        return b""
    reported = int(payload[0])
    if reported >= 2:
        end = min(len(payload), 1 + reported)
        return payload[3:end]
    return payload[3:]


def extract_bits_msb(data: bytes, bix: int, blen: int) -> Optional[int]:
    if blen <= 0:
        return None
    total_bits = len(data) * 8
    if bix < 0 or bix + blen > total_bits:
        return None

    buf = int.from_bytes(data, byteorder="big", signed=False)
    shift = total_bits - (bix + blen)
    return (buf >> shift) & ((1 << blen) - 1)


def decode_signal(signal_def: Dict, data_bytes: bytes) -> Optional[str]:
    fmt = signal_def.get("fmt") or {}
    bix = int(fmt.get("bix", 0))
    blen = int(fmt.get("len", 0))
    raw = extract_bits_msb(data_bytes, bix=bix, blen=blen)
    if raw is None:
        return None

    sid = str(signal_def.get("id") or signal_def.get("name") or "signal")
    unit = fmt.get("unit")

    if "map" in fmt and isinstance(fmt["map"], dict):
        mapped = fmt["map"].get(str(raw))
        if mapped is None:
            return f"{sid}={raw}"
        if isinstance(mapped, dict):
            value = mapped.get("value", mapped.get("description", raw))
            return f"{sid}={value}"
        return f"{sid}={mapped}"

    val = float(raw)
    if "mul" in fmt:
        val *= float(fmt["mul"])
    if "div" in fmt and float(fmt["div"]) != 0:
        val /= float(fmt["div"])
    if "add" in fmt:
        val += float(fmt["add"])

    if val.is_integer():
        rendered = str(int(val))
    else:
        rendered = f"{val:.6f}".rstrip("0").rstrip(".")
    if unit:
        return f"{sid}={rendered} {unit}"
    return f"{sid}={rendered}"


def decode_pid_payload(command: PollCommand, payload: bytes) -> List[str]:
    data_bytes = response_data_bytes(payload)
    decoded: List[str] = []
    for signal_def in command.signals:
        value = decode_signal(signal_def, data_bytes)
        if value is not None:
            decoded.append(value)
    return decoded


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan supported OBD-II PIDs then poll supported Mode 01 PIDs."
    )
    parser.add_argument("-i", "--interface", default="can0", help="CAN interface name")
    parser.add_argument(
        "--json",
        default="src/carbus/data/saej1979_default.json",
        help="Path to SAEJ1979 JSON file",
    )
    parser.add_argument(
        "--request-id",
        default="0x7E0",
        help="CAN ID used for OBD requests (example: 0x7DF or 0x7E0)",
    )
    parser.add_argument(
        "--response-id",
        default="0x7E8",
        help="Primary expected CAN response ID from ECU",
    )
    parser.add_argument(
        "--response-range",
        action="store_true",
        help="Accept responses from 0x7E8 through 0x7EF",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout in seconds while waiting for PID responses",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    json_path = Path(args.json)
    if not json_path.exists():
        raise FileNotFoundError(f"JSON file not found: {json_path}")

    request_id = parse_can_id(args.request_id)
    primary_response = parse_can_id(args.response_id)
    response_ids = (
        set(range(0x7E8, 0x7F0)) if args.response_range else {primary_response}
    )

    sock = SocketCAN()
    sock.setblocking(True)
    sock.set_can_filters(
        [CANFilter(can_id=rid, mask=CANFilter.SFF_MASK) for rid in sorted(response_ids)]
    )
    sock.bind(args.interface)

    stop = False

    def _stop_handler(signum, frame):  # pylint: disable=unused-argument
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop_handler)
    signal.signal(signal.SIGTERM, _stop_handler)

    query_and_print_dtcs(
        sock=sock,
        request_id=request_id,
        response_ids=response_ids,
        timeout_s=args.timeout,
    )

    print(f"Scanning supported Mode 01 PIDs on {args.interface}...")
    supported_mode01 = scan_supported_mode01_pids(
        sock=sock,
        request_id=request_id,
        response_ids=response_ids,
        timeout_s=args.timeout,
    )
    print(f"Supported Mode 01 PIDs: {len(supported_mode01)} found")
    print(" ".join(f"{pid:02X}" for pid in sorted(supported_mode01)))

    commands = load_mode01_commands(json_path)
    plan = build_poll_plan(commands, supported_mode01, now=time.monotonic())
    if not plan:
        print("No pollable supported Mode 01 PIDs found in the JSON command set.")
        return 0

    print(f"Polling {len(plan)} supported PIDs based on JSON freq values...")
    for cmd in plan:
        print(f"  PID 0x{cmd.pid:02X} every {cmd.period_s}s ({cmd.name})")

    while not stop:
        now = time.monotonic()
        due_cmd = min(plan, key=lambda c: c.next_due)
        sleep_for = due_cmd.next_due - now
        if sleep_for > 0:
            time.sleep(min(sleep_for, 0.05))
            continue

        sock.write(mk_obd_request(due_cmd.mode, due_cmd.pid), request_id, rtr=False)
        data = wait_for_response(
            sock=sock,
            mode=due_cmd.mode,
            pid=due_cmd.pid,
            timeout_s=args.timeout,
            response_ids=response_ids,
        )
        ts = time.strftime("%H:%M:%S")
        if data is None:
            print(f"[{ts}] PID 0x{due_cmd.pid:02X} timeout")
        else:
            decoded = decode_pid_payload(due_cmd, data)
            if decoded:
                print(f"[{ts}] PID 0x{due_cmd.pid:02X} {due_cmd.name}: " + ", ".join(decoded))
            else:
                print(f"[{ts}] PID 0x{due_cmd.pid:02X} {due_cmd.name}: {data.hex()}")
        due_cmd.next_due = max(due_cmd.next_due + due_cmd.period_s, time.monotonic())

    print("Stopping.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
