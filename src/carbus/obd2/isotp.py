"""ISO-TP (ISO 15765-2) transport implemented on top of carbus SocketCAN."""

import select
import time
from typing import Iterable, Optional, Set

from carbus.can.SocketCAN import CANFrame, SocketCAN


class IsoTpError(RuntimeError):
    pass


class IsoTpTimeout(IsoTpError):
    pass


class IsoTpSequenceError(IsoTpError):
    pass


class IsoTpFlowControlError(IsoTpError):
    pass


def _stmin_to_seconds(stmin: int) -> float:
    if 0x00 <= stmin <= 0x7F:
        return stmin / 1000.0
    if 0xF1 <= stmin <= 0xF9:
        return (stmin - 0xF0) / 10000.0
    return 0.0


class IsoTpTransport:
    """Minimal ISO-TP request/response transport for 11-bit CAN IDs."""

    def __init__(
        self,
        sock: SocketCAN,
        request_id: int,
        response_ids: Iterable[int],
        timeout_s: float = 1.0,
        tx_padding: int = 0x00,
        max_wait_fc: int = 8,
    ):
        self.sock = sock
        self.request_id = int(request_id)
        self.response_ids: Set[int] = {int(x) for x in response_ids}
        self.timeout_s = float(timeout_s)
        self.tx_padding = tx_padding & 0xFF
        self.max_wait_fc = max_wait_fc

    def request(self, payload: bytes) -> bytes:
        self.send(payload)
        return self.receive()

    def send(self, payload: bytes) -> None:
        if len(payload) <= 7:
            frame = bytes([len(payload) & 0x0F]) + payload
            self._send_frame(frame)
            return

        total_len = len(payload)
        if total_len > 0xFFF:
            raise IsoTpError("Payloads > 4095 bytes are not supported")

        first = bytes(
            [
                0x10 | ((total_len >> 8) & 0x0F),
                total_len & 0xFF,
            ]
        ) + payload[:6]
        self._send_frame(first)

        bs, stmin = self._wait_for_flow_control()
        idx = 6
        sn = 1
        sent_in_block = 0
        delay_s = _stmin_to_seconds(stmin)

        while idx < total_len:
            chunk = payload[idx : idx + 7]
            cf = bytes([0x20 | (sn & 0x0F)]) + chunk
            self._send_frame(cf)
            idx += len(chunk)
            sn = (sn + 1) & 0x0F
            sent_in_block += 1

            if delay_s > 0:
                time.sleep(delay_s)

            if bs != 0 and sent_in_block >= bs and idx < total_len:
                bs, stmin = self._wait_for_flow_control()
                delay_s = _stmin_to_seconds(stmin)
                sent_in_block = 0

    def receive(self) -> bytes:
        deadline = time.monotonic() + self.timeout_s
        first = self._read_response_frame(deadline)
        if first is None:
            raise IsoTpTimeout("Timed out waiting for first ISO-TP frame")
        if len(first.data) == 0:
            raise IsoTpError("Received empty CAN frame")

        pci = first.data[0]
        frame_type = (pci >> 4) & 0x0F

        if frame_type == 0x0:
            payload_len = pci & 0x0F
            return bytes(first.data[1 : 1 + payload_len])

        if frame_type != 0x1 or len(first.data) < 2:
            raise IsoTpError("Unsupported first frame type")

        total_len = ((pci & 0x0F) << 8) | first.data[1]
        payload = bytearray(first.data[2:])
        if len(payload) > total_len:
            payload = payload[:total_len]

        self._send_flow_control_cts()

        expected_sn = 1
        while len(payload) < total_len:
            cf = self._read_response_frame(deadline)
            if cf is None:
                raise IsoTpTimeout("Timed out waiting for consecutive frame")
            if len(cf.data) == 0:
                continue

            cf_type = (cf.data[0] >> 4) & 0x0F
            if cf_type != 0x2:
                continue

            sn = cf.data[0] & 0x0F
            if sn != expected_sn:
                raise IsoTpSequenceError(
                    f"Consecutive frame SN mismatch: expected {expected_sn}, got {sn}"
                )

            payload.extend(cf.data[1:])
            expected_sn = (expected_sn + 1) & 0x0F

        return bytes(payload[:total_len])

    def _send_frame(self, data: bytes) -> None:
        self.sock.write(self._pad_to_8(data), self.request_id, rtr=False)

    def _send_flow_control_cts(self) -> None:
        self._send_frame(bytes([0x30, 0x00, 0x00]))

    def _wait_for_flow_control(self) -> tuple[int, int]:
        deadline = time.monotonic() + self.timeout_s
        wait_count = 0

        while True:
            frame = self._read_response_frame(deadline)
            if frame is None:
                raise IsoTpTimeout("Timed out waiting for flow control frame")
            if len(frame.data) < 3:
                continue
            if ((frame.data[0] >> 4) & 0x0F) != 0x3:
                continue

            fs = frame.data[0] & 0x0F
            bs = frame.data[1]
            stmin = frame.data[2]

            if fs == 0x0:
                return bs, stmin
            if fs == 0x1:
                wait_count += 1
                if wait_count > self.max_wait_fc:
                    raise IsoTpFlowControlError("Too many WAIT flow-control frames")
                continue
            if fs == 0x2:
                raise IsoTpFlowControlError("Receiver reported buffer overflow")
            raise IsoTpFlowControlError(f"Invalid flow-control status: {fs}")

    def _read_response_frame(self, deadline: float) -> Optional[CANFrame]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select([self.sock], [], [], remaining)
            if not readable:
                return None
            frame = self.sock.read()
            if frame.addr in self.response_ids:
                return frame

    def _pad_to_8(self, data: bytes) -> bytes:
        if len(data) >= 8:
            return data[:8]
        return data + bytes([self.tx_padding] * (8 - len(data)))
