"""UDS (ISO 14229-1) client built on top of IsoTpTransport."""

from dataclasses import dataclass
from typing import Optional

from carbus.obd2.isotp import IsoTpTimeout, IsoTpTransport


class UdsError(RuntimeError):
    pass


class UdsNegativeResponse(UdsError):
    def __init__(self, request_sid: int, nrc: int):
        super().__init__(f"UDS negative response SID=0x{request_sid:02X} NRC=0x{nrc:02X}")
        self.request_sid = request_sid
        self.nrc = nrc


class UdsResponseMismatch(UdsError):
    pass


class ServiceID:
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    READ_DATA_BY_IDENTIFIER = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    SECURITY_ACCESS = 0x27
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    ROUTINE_CONTROL = 0x31
    TESTER_PRESENT = 0x3E


class NegativeResponseCode:
    REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING = 0x78


@dataclass
class UdsClient:
    tp: IsoTpTransport
    pending_retries: int = 8

    def request(self, service_id: int, payload: bytes = b"") -> bytes:
        request = bytes([service_id & 0xFF]) + payload
        response = self.tp.request(request)
        return self._parse_response(service_id, response)

    def diagnostic_session_control(self, session_type: int) -> bytes:
        return self.request(ServiceID.DIAGNOSTIC_SESSION_CONTROL, bytes([session_type & 0x7F]))

    def ecu_reset(self, reset_type: int) -> bytes:
        return self.request(ServiceID.ECU_RESET, bytes([reset_type & 0x7F]))

    def tester_present(self, suppress_positive_response: bool = False) -> Optional[bytes]:
        sub = 0x80 if suppress_positive_response else 0x00
        resp = self.request(ServiceID.TESTER_PRESENT, bytes([sub]))
        if suppress_positive_response:
            return None
        return resp

    def read_data_by_identifier(self, did: int) -> bytes:
        req = bytes([(did >> 8) & 0xFF, did & 0xFF])
        response = self.request(ServiceID.READ_DATA_BY_IDENTIFIER, req)
        if len(response) < 2:
            raise UdsResponseMismatch("RDBI response too short")
        response_did = (response[0] << 8) | response[1]
        if response_did != did:
            raise UdsResponseMismatch(
                f"RDBI DID mismatch: expected 0x{did:04X}, got 0x{response_did:04X}"
            )
        return response[2:]

    def security_access_request_seed(self, level: int) -> bytes:
        response = self.request(ServiceID.SECURITY_ACCESS, bytes([level & 0x7F]))
        if not response:
            raise UdsResponseMismatch("SecurityAccess seed response too short")
        if response[0] != (level & 0x7F):
            raise UdsResponseMismatch(
                f"SecurityAccess level mismatch: expected 0x{level:02X}, got 0x{response[0]:02X}"
            )
        return response[1:]

    def security_access_send_key(self, level: int, key: bytes) -> bytes:
        payload = bytes([level & 0x7F]) + key
        response = self.request(ServiceID.SECURITY_ACCESS, payload)
        if not response:
            raise UdsResponseMismatch("SecurityAccess key response too short")
        if response[0] != (level & 0x7F):
            raise UdsResponseMismatch(
                f"SecurityAccess level mismatch: expected 0x{level:02X}, got 0x{response[0]:02X}"
            )
        return response[1:]

    def _parse_response(self, requested_sid: int, response: bytes) -> bytes:
        retries_left = self.pending_retries
        current = response

        while True:
            if not current:
                raise UdsResponseMismatch("Empty UDS response payload")

            sid = current[0]
            if sid == 0x7F:
                if len(current) < 3:
                    raise UdsResponseMismatch("Negative response too short")
                original_sid = current[1]
                nrc = current[2]
                if (
                    nrc == NegativeResponseCode.REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING
                    and retries_left > 0
                ):
                    retries_left -= 1
                    try:
                        current = self.tp.receive()
                        continue
                    except IsoTpTimeout as exc:
                        raise UdsError("Timed out while waiting for NRC 0x78 completion") from exc
                raise UdsNegativeResponse(original_sid, nrc)

            expected_sid = (requested_sid + 0x40) & 0xFF
            if sid != expected_sid:
                raise UdsResponseMismatch(
                    f"Unexpected response SID: expected 0x{expected_sid:02X}, got 0x{sid:02X}"
                )
            return current[1:]
