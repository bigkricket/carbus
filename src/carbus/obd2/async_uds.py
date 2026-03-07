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

    async def tester_present(self, suppress_positive_response: bool = False) -> Optional[bytes]:
        return await asyncio.to_thread(self.client.tester_present, suppress_positive_response)

    async def read_data_by_identifier(self, did: int) -> bytes:
        return await asyncio.to_thread(self.client.read_data_by_identifier, did)

    async def security_access_request_seed(self, level: int) -> bytes:
        return await asyncio.to_thread(self.client.security_access_request_seed, level)

    async def security_access_send_key(self, level: int, key: bytes) -> bytes:
        return await asyncio.to_thread(self.client.security_access_send_key, level, key)
