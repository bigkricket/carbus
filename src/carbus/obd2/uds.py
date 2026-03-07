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
    CLEAR_DIAGNOSTIC_INFORMATION = 0x14
    READ_DTC_INFORMATION = 0x19
    READ_DATA_BY_IDENTIFIER = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    SECURITY_ACCESS = 0x27
    COMMUNICATION_CONTROL = 0x28
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2F
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37
    WRITE_MEMORY_BY_ADDRESS = 0x3D
    TESTER_PRESENT = 0x3E
    CONTROL_DTC_SETTING = 0x85


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

    def clear_diagnostic_information(self, dtc_group: int = 0xFFFFFF) -> bytes:
        payload = bytes([(dtc_group >> 16) & 0xFF, (dtc_group >> 8) & 0xFF, dtc_group & 0xFF])
        return self.request(ServiceID.CLEAR_DIAGNOSTIC_INFORMATION, payload)

    def read_dtc_information(self, report_type: int, payload: bytes = b"") -> bytes:
        return self.request(ServiceID.READ_DTC_INFORMATION, bytes([report_type & 0xFF]) + payload)

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

    def read_memory_by_address(self, address_and_length_format_id: int, address_and_length: bytes) -> bytes:
        payload = bytes([address_and_length_format_id & 0xFF]) + address_and_length
        return self.request(ServiceID.READ_MEMORY_BY_ADDRESS, payload)

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

    def communication_control(self, control_type: int, communication_type: int, node_id: bytes = b"") -> bytes:
        payload = bytes([control_type & 0x7F, communication_type & 0xFF]) + node_id
        return self.request(ServiceID.COMMUNICATION_CONTROL, payload)

    def write_data_by_identifier(self, did: int, value: bytes) -> bytes:
        payload = bytes([(did >> 8) & 0xFF, did & 0xFF]) + value
        response = self.request(ServiceID.WRITE_DATA_BY_IDENTIFIER, payload)
        if len(response) < 2:
            raise UdsResponseMismatch("WDBI response too short")
        response_did = (response[0] << 8) | response[1]
        if response_did != did:
            raise UdsResponseMismatch(
                f"WDBI DID mismatch: expected 0x{did:04X}, got 0x{response_did:04X}"
            )
        return response[2:]

    def input_output_control_by_identifier(
        self,
        did: int,
        control_option_record: bytes,
        control_enable_mask_record: bytes = b"",
    ) -> bytes:
        payload = (
            bytes([(did >> 8) & 0xFF, did & 0xFF])
            + control_option_record
            + control_enable_mask_record
        )
        return self.request(ServiceID.INPUT_OUTPUT_CONTROL_BY_IDENTIFIER, payload)

    def routine_control(self, routine_control_type: int, routine_id: int, option_record: bytes = b"") -> bytes:
        payload = bytes(
            [
                routine_control_type & 0x7F,
                (routine_id >> 8) & 0xFF,
                routine_id & 0xFF,
            ]
        ) + option_record
        return self.request(ServiceID.ROUTINE_CONTROL, payload)

    def request_download(self, data_format_identifier: int, address_and_length_format_id: int, memory_address_and_size: bytes) -> bytes:
        payload = (
            bytes([data_format_identifier & 0xFF, address_and_length_format_id & 0xFF])
            + memory_address_and_size
        )
        return self.request(ServiceID.REQUEST_DOWNLOAD, payload)

    def request_upload(self, data_format_identifier: int, address_and_length_format_id: int, memory_address_and_size: bytes) -> bytes:
        payload = (
            bytes([data_format_identifier & 0xFF, address_and_length_format_id & 0xFF])
            + memory_address_and_size
        )
        return self.request(ServiceID.REQUEST_UPLOAD, payload)

    def transfer_data(self, block_sequence_counter: int, transfer_request_parameter_record: bytes) -> bytes:
        payload = bytes([block_sequence_counter & 0xFF]) + transfer_request_parameter_record
        return self.request(ServiceID.TRANSFER_DATA, payload)

    def request_transfer_exit(self, transfer_request_parameter_record: bytes = b"") -> bytes:
        return self.request(ServiceID.REQUEST_TRANSFER_EXIT, transfer_request_parameter_record)

    def write_memory_by_address(self, address_and_length_format_id: int, memory_address_and_size: bytes, data_record: bytes) -> bytes:
        payload = (
            bytes([address_and_length_format_id & 0xFF])
            + memory_address_and_size
            + data_record
        )
        return self.request(ServiceID.WRITE_MEMORY_BY_ADDRESS, payload)

    def control_dtc_setting(self, dtc_setting_type: int, dtc_setting_control_option_record: bytes = b"") -> bytes:
        payload = bytes([dtc_setting_type & 0x7F]) + dtc_setting_control_option_record
        return self.request(ServiceID.CONTROL_DTC_SETTING, payload)

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
