"""Async wrappers around the blocking ISO-TP/UDS client classes."""

import asyncio
from dataclasses import dataclass
from typing import Optional

from carbus.obd2.uds import UdsClient


@dataclass
class AsyncUdsClient:
    """Run UDS requests in a thread to avoid blocking asyncio loops."""

    client: UdsClient

    async def request(self, service_id: int, payload: bytes = b"") -> bytes:
        return await asyncio.to_thread(self.client.request, service_id, payload)

    async def diagnostic_session_control(self, session_type: int) -> bytes:
        return await asyncio.to_thread(self.client.diagnostic_session_control, session_type)

    async def ecu_reset(self, reset_type: int) -> bytes:
        return await asyncio.to_thread(self.client.ecu_reset, reset_type)

    async def clear_diagnostic_information(self, dtc_group: int = 0xFFFFFF) -> bytes:
        return await asyncio.to_thread(self.client.clear_diagnostic_information, dtc_group)

    async def read_dtc_information(self, report_type: int, payload: bytes = b"") -> bytes:
        return await asyncio.to_thread(self.client.read_dtc_information, report_type, payload)

    async def tester_present(self, suppress_positive_response: bool = False) -> Optional[bytes]:
        return await asyncio.to_thread(self.client.tester_present, suppress_positive_response)

    async def read_data_by_identifier(self, did: int) -> bytes:
        return await asyncio.to_thread(self.client.read_data_by_identifier, did)

    async def read_memory_by_address(self, address_and_length_format_id: int, address_and_length: bytes) -> bytes:
        return await asyncio.to_thread(
            self.client.read_memory_by_address,
            address_and_length_format_id,
            address_and_length,
        )

    async def security_access_request_seed(self, level: int) -> bytes:
        return await asyncio.to_thread(self.client.security_access_request_seed, level)

    async def security_access_send_key(self, level: int, key: bytes) -> bytes:
        return await asyncio.to_thread(self.client.security_access_send_key, level, key)

    async def communication_control(self, control_type: int, communication_type: int, node_id: bytes = b"") -> bytes:
        return await asyncio.to_thread(
            self.client.communication_control,
            control_type,
            communication_type,
            node_id,
        )

    async def write_data_by_identifier(self, did: int, value: bytes) -> bytes:
        return await asyncio.to_thread(self.client.write_data_by_identifier, did, value)

    async def input_output_control_by_identifier(
        self,
        did: int,
        control_option_record: bytes,
        control_enable_mask_record: bytes = b"",
    ) -> bytes:
        return await asyncio.to_thread(
            self.client.input_output_control_by_identifier,
            did,
            control_option_record,
            control_enable_mask_record,
        )

    async def routine_control(
        self,
        routine_control_type: int,
        routine_id: int,
        option_record: bytes = b"",
    ) -> bytes:
        return await asyncio.to_thread(
            self.client.routine_control,
            routine_control_type,
            routine_id,
            option_record,
        )

    async def request_download(
        self,
        data_format_identifier: int,
        address_and_length_format_id: int,
        memory_address_and_size: bytes,
    ) -> bytes:
        return await asyncio.to_thread(
            self.client.request_download,
            data_format_identifier,
            address_and_length_format_id,
            memory_address_and_size,
        )

    async def request_upload(
        self,
        data_format_identifier: int,
        address_and_length_format_id: int,
        memory_address_and_size: bytes,
    ) -> bytes:
        return await asyncio.to_thread(
            self.client.request_upload,
            data_format_identifier,
            address_and_length_format_id,
            memory_address_and_size,
        )

    async def transfer_data(self, block_sequence_counter: int, transfer_request_parameter_record: bytes) -> bytes:
        return await asyncio.to_thread(
            self.client.transfer_data,
            block_sequence_counter,
            transfer_request_parameter_record,
        )

    async def request_transfer_exit(self, transfer_request_parameter_record: bytes = b"") -> bytes:
        return await asyncio.to_thread(
            self.client.request_transfer_exit,
            transfer_request_parameter_record,
        )

    async def write_memory_by_address(
        self,
        address_and_length_format_id: int,
        memory_address_and_size: bytes,
        data_record: bytes,
    ) -> bytes:
        return await asyncio.to_thread(
            self.client.write_memory_by_address,
            address_and_length_format_id,
            memory_address_and_size,
            data_record,
        )

    async def control_dtc_setting(
        self,
        dtc_setting_type: int,
        dtc_setting_control_option_record: bytes = b"",
    ) -> bytes:
        return await asyncio.to_thread(
            self.client.control_dtc_setting,
            dtc_setting_type,
            dtc_setting_control_option_record,
        )
