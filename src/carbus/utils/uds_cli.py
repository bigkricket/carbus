#!/usr/bin/env python3
"""Simple UDS CLI for carbus."""

import argparse
import select
import sys
import time
from typing import Iterable, Optional

from carbus.can.SocketCAN import SocketCAN
from carbus.obd2 import (
    IsoTpTransport,
    ServiceID,
    UdsClient,
    UdsNegativeResponse,
)


SERVICE_NAMES = {
    0x10: "DIAGNOSTIC_SESSION_CONTROL",
    0x11: "ECU_RESET",
    0x14: "CLEAR_DIAGNOSTIC_INFORMATION",
    0x19: "READ_DTC_INFORMATION",
    0x22: "READ_DATA_BY_IDENTIFIER",
    0x23: "READ_MEMORY_BY_ADDRESS",
    0x27: "SECURITY_ACCESS",
    0x28: "COMMUNICATION_CONTROL",
    0x2E: "WRITE_DATA_BY_IDENTIFIER",
    0x2F: "INPUT_OUTPUT_CONTROL_BY_IDENTIFIER",
    0x31: "ROUTINE_CONTROL",
    0x34: "REQUEST_DOWNLOAD",
    0x35: "REQUEST_UPLOAD",
    0x36: "TRANSFER_DATA",
    0x37: "REQUEST_TRANSFER_EXIT",
    0x3D: "WRITE_MEMORY_BY_ADDRESS",
    0x3E: "TESTER_PRESENT",
    0x85: "CONTROL_DTC_SETTING",
}


def parse_int(raw: str) -> int:
    return int(raw, 0)


def parse_hex_bytes(raw: Optional[str]) -> bytes:
    if raw is None or raw == "":
        return b""
    cleaned = raw.replace(" ", "").replace(":", "").replace("-", "")
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex payload must have an even number of nibbles")
    return bytes.fromhex(cleaned)


def fmt_bytes(data: bytes) -> str:
    return data.hex().upper() if data else "(empty)"


def mk_client(
    interface: str,
    src: int,
    dst: int,
    timeout_s: float,
) -> tuple[SocketCAN, UdsClient]:
    sock = SocketCAN()
    sock.bind(interface)
    tp = IsoTpTransport(sock, request_id=src, response_ids={dst}, timeout_s=timeout_s)
    return sock, UdsClient(tp)


def _extract_uds_payload(frame_data: bytes) -> Optional[bytes]:
    if not frame_data:
        return None
    pci = frame_data[0]
    frame_type = (pci >> 4) & 0x0F
    if frame_type == 0x0:
        payload_len = pci & 0x0F
        return bytes(frame_data[1 : 1 + payload_len])
    if frame_type == 0x1 and len(frame_data) >= 3:
        return bytes(frame_data[2:])
    return None


def _is_dsc_response(payload: bytes, session_type: int) -> bool:
    if not payload:
        return False
    if payload[0] == 0x50:
        return len(payload) >= 2 and payload[1] == (session_type & 0x7F)
    if payload[0] == 0x7F:
        return len(payload) >= 3 and payload[1] == ServiceID.DIAGNOSTIC_SESSION_CONTROL
    return False


def _probe_once(
    sock: SocketCAN,
    req_id: int,
    session_type: int,
    timeout_s: float,
) -> set[int]:
    request = bytes([0x02, ServiceID.DIAGNOSTIC_SESSION_CONTROL, session_type & 0x7F, 0, 0, 0, 0, 0])
    sock.write(request, req_id, rtr=False)

    found: set[int] = set()
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        readable, _, _ = select.select([sock], [], [], remaining)
        if not readable:
            break
        frame = sock.read()
        if frame.addr == req_id:
            continue
        payload = _extract_uds_payload(frame.data)
        if payload is None:
            continue
        if _is_dsc_response(payload, session_type):
            found.add(frame.addr)
    return found


def cmd_request(args: argparse.Namespace) -> int:
    sock, uds = mk_client(args.interface, args.src, args.dst, args.timeout)
    try:
        payload = parse_hex_bytes(args.data)
        response = uds.request(args.sid, payload)
        print(fmt_bytes(response))
        return 0
    finally:
        sock.close()


def cmd_session(args: argparse.Namespace) -> int:
    sock, uds = mk_client(args.interface, args.src, args.dst, args.timeout)
    try:
        response = uds.diagnostic_session_control(args.session_type)
        print(fmt_bytes(response))
        return 0
    finally:
        sock.close()


def cmd_read_did(args: argparse.Namespace) -> int:
    sock, uds = mk_client(args.interface, args.src, args.dst, args.timeout)
    try:
        value = uds.read_data_by_identifier(args.did)
        print(fmt_bytes(value))
        return 0
    finally:
        sock.close()


def _iter_services() -> Iterable[int]:
    return range(0x00, 0x100)


def cmd_services(args: argparse.Namespace) -> int:
    sock, uds = mk_client(args.interface, args.src, args.dst, args.timeout)
    supported = []
    try:
        for sid in _iter_services():
            try:
                uds.request(sid, b"")
                supported.append((sid, None))
            except UdsNegativeResponse as exc:
                # 0x11 means "service not supported"; anything else implies
                # service is recognized but request details were invalid.
                if exc.nrc != 0x11:
                    supported.append((sid, exc.nrc))
            except Exception:
                continue

        for sid, nrc in supported:
            name = SERVICE_NAMES.get(sid, "Unknown service")
            if nrc is None:
                print(f"0x{sid:02X} {name}")
            else:
                print(f"0x{sid:02X} {name} (NRC=0x{nrc:02X})")
        return 0
    finally:
        sock.close()


def cmd_discovery(args: argparse.Namespace) -> int:
    sock = SocketCAN()
    sock.bind(args.interface)
    try:
        results = []
        for req_id in range(args.min_id, args.max_id + 1):
            first = _probe_once(sock, req_id, args.session_type, args.timeout)
            if not first:
                continue
            if args.verify:
                second = _probe_once(sock, req_id, args.session_type, args.timeout)
                first = first.intersection(second)
                if not first:
                    continue
            for resp_id in sorted(first):
                results.append((req_id, resp_id))
                print(f"Found diagnostics server: request=0x{req_id:03X} response=0x{resp_id:03X}")

        if not results:
            print("No UDS responders found in scan range")
            return 0

        print("\nSummary")
        for req_id, resp_id in results:
            print(f"0x{req_id:03X} -> 0x{resp_id:03X}")
        return 0
    finally:
        sock.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="UDS tooling over carbus SocketCAN stack")
    p.add_argument("-i", "--interface", default="can0", help="SocketCAN interface")
    sub = p.add_subparsers(dest="cmd", required=True)

    disc = sub.add_parser("discovery", help="Discover UDS request/response ID pairs")
    disc.add_argument("--min-id", type=parse_int, default=0x700, help="Min request CAN ID")
    disc.add_argument("--max-id", type=parse_int, default=0x7FF, help="Max request CAN ID")
    disc.add_argument(
        "--session-type",
        type=parse_int,
        default=0x01,
        help="Diagnostic Session Control type to probe",
    )
    disc.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.05,
        help="Per-request listen timeout in seconds",
    )
    disc.add_argument(
        "--no-verify",
        action="store_false",
        dest="verify",
        help="Skip second probe verification",
    )
    disc.set_defaults(func=cmd_discovery, verify=True)

    req = sub.add_parser("request", help="Send raw UDS request")
    req.add_argument("src", type=parse_int, help="Request CAN ID")
    req.add_argument("dst", type=parse_int, help="Response CAN ID")
    req.add_argument("sid", type=parse_int, help="UDS service ID")
    req.add_argument("--data", default="", help="Hex payload bytes (no SID)")
    req.add_argument("-t", "--timeout", type=float, default=1.0, help="Response timeout")
    req.set_defaults(func=cmd_request)

    ses = sub.add_parser("session", help="DiagnosticSessionControl")
    ses.add_argument("session_type", type=parse_int, help="Session type")
    ses.add_argument("src", type=parse_int, help="Request CAN ID")
    ses.add_argument("dst", type=parse_int, help="Response CAN ID")
    ses.add_argument("-t", "--timeout", type=float, default=1.0, help="Response timeout")
    ses.set_defaults(func=cmd_session)

    did = sub.add_parser("read-did", help="ReadDataByIdentifier")
    did.add_argument("did", type=parse_int, help="DID")
    did.add_argument("src", type=parse_int, help="Request CAN ID")
    did.add_argument("dst", type=parse_int, help="Response CAN ID")
    did.add_argument("-t", "--timeout", type=float, default=1.0, help="Response timeout")
    did.set_defaults(func=cmd_read_did)

    sv = sub.add_parser("services", help="Probe ECU for supported service IDs")
    sv.add_argument("src", type=parse_int, help="Request CAN ID")
    sv.add_argument("dst", type=parse_int, help="Response CAN ID")
    sv.add_argument("-t", "--timeout", type=float, default=0.2, help="Per-request timeout")
    sv.set_defaults(func=cmd_services)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
