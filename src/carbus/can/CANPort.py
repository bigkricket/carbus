"""
File: CANPort.py
Author: Ruben Perez

Description:
	This file contains the implementation of a asyncio-based CAN
Port object. This provides a mechanism to insert CAN message
processing/listening into asyncio's reactor framework.
"""

import logging
import traceback
import asyncio

from zope.interface import Interface, implementer
from asyncio import Transport

from .SocketCAN import CANError, SocketCAN, socket


class ICANTransport(Interface):
	"""Transport for raw CAN datagram packets"""

	def write(data, addr, rtr=False):
		"""Send a CAN frame
		@param data string of up to 8 bytes. Message will truncate
		  at 8 bytes.
		@param addr address of the node we are sending a message to.
		@param rtr Remote Transmission Request - used to pull messages
		   from another node.
		"""
		pass

	def setFilters(self, filters):
		"""Configure a set of filters on the CAN port
		@param list of CANFilter objects
		"""
		pass

	def getFilters(self):
		"""Retrieve the current filter set for the CAN port
		@return list of CANFilters objects
		"""
		pass

	def getHost():
		"""Get the interface name that this transport is connected to."""
		pass

	def stopListening():
		pass


class AlreadyConnectedError(RuntimeError):
	pass

@implementer(interfaces.IListeningPort, ICANTransport, interfaces.ISystemHandle)
class CANPort(Transport):
	addressFamily = socket.AF_CAN
	socketType = socket.SOCK_RAW
	maxFrameSize = 8

	AlreadyConnectedError = AlreadyConnectedError
	
	def __init__(self, ifname, proto, loop=None):
		"""Create a new CAN port object
		@param ifname name of the CAN interface, such as `can0`
		@param proto object implementing the CANProtocol interface
		  that receives messages from the bus.
		@param filters list of CANFilter objects that are the
		  default filters for the port.
		@param reactor reactor to use for this port, if None, we use
		  the default global reactor.
		"""
		super().__init__(self)

		self.ifname = ifname
		self.protocol = proto

		self.socket = None
		self.fileno = None
		self.loop = loop
		self.reader = None
		self.writer = None

	def getHandle(self):
		return self.socket
	
	def startListening(self):
		if self.loop is None:
			self.loop = asyncio.get_event_loop()
		self._bindSocket()
		self._connectToProtocol(self.protocol)

	def stopListening(self):
		if self.socket:
			self.loop.remove_reader(self.fileno)

	async def connectionLost(self, reason=None):
		await self.protocol.doStop()
		self.socket.close()
		self.socket = None
		self.fileno = None
	
	def doRead(self):
		try:
			frame = self.socket.read()
			if isinstance(frame, CANError):
				logging.error("{}: Error frame: {}".format(self.ifname, frame))
				logging.debug(traceback.format_exc())
				self.protocol.errorFrameReceived(frame)
				return
		except Exception as exc:
			logging.error("{} Read: {}".format(self.ifname, exc))
			logging.debug(traceback.format_exc())
			return
		try:
			self.protocol.frameReceived(frame)
		except Exception as exc:
			logging.error("{} frameReceived: {}".format(self.ifname, exc))
			logging.debug(traceback.format_exc())
	
	def write(self, frame):
		"""Write a CAN frame to the port
		@param frame data to write in the form of a CANFrame object
		"""
		self.socket.write(frame.data, frame.addr, frame.rtr)
	
	def getTimestamp(self):
		return self.socket.get_timestamp()

	def setFilters(self, filters):
		self.socket.set_can_filters(filters)

	def getFilters(self):
		return self.socket.get_can_filters()

	def getHost(self):
		"""Returns the interface name and index"""
		return (self.ifname, self.socket.ifindex)

	def logPrefix(self):
		return self.logstr

	def setLogStr(self):
		logPrefix = self._getLogPrefix(self.protocol)
		self.logstr = "{} (CAN)".format(logPrefix)

	def _bindSocket(self):
		skt = SocketCAN()
		skt.setblocking(False)
		skt.set_error_mask()
		filters = self.protocol.getFilters()
		if len(filters) > 0:
			skt.set_can_filters(filters)
		
		try:
			skt.bind(self.ifname)
		except socket.error as exc:
			raise ConnectionRefusedError(self.ifname, 0, exc)

		logging.info(f"CANProtocol starting on {self.ifname}")

		self.socket = skt
		self.fileno = self.socket.fileno

	def _connectToProtocol(self):
		self.protocol.makeConnection(self)
		self.loop.add_reader(self.fileno, lambda: self.doRead())

class CANPortCollection(object):
	"""Class for managing multiple CANPort sockets"""

	def __init__(self, ifname):
		self._ifname = ifname
		if not SocketCAN.is_up(self._ifname):
			raise RuntimeError("CAN Interface {} is not Up".format(self._ifname))
		self._socks = []
		self._started = False

	@property
	def sockets(self):
		return self._socks

	def get_interface(self):
		return self._ifname

	def add_socket(self, proto):
		if proto.transport is not None:
			raise AlreadyConnectedError(
				"Protocol {} Already Connected".format(str(proto))
			)

		sock = CANPort(self._ifname, proto)
		if self._started:
			sock.startListening()
		self._socks.append(sock)

	async def remove_socket(self, proto):
		sock = self._match_socket(proto)
		if sock is None:
			return
		self._socks.remove(sock)
		await sock.stopListening()

	async def cleanup_sockets(self):
		if self._started:
			for sock in self._socks:
				await sock.stopListening()
		self._socks = []

	def startListening(self):
		for sock in self._socks:
			sock.startListening()

		self._started = True

	def stopListening(self):
		for x in self._socks:
			x.stopListening

	def _match_socket(self, proto):
		for sock in self._socks:
			if sock.protocol == proto:
				return sock
		return None