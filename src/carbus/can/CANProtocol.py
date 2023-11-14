"""
File: CANProtocol.py

This module contains the implementation of a protocol interface for the
raw SocketCAN sockets. 
"""

from asyncio import Protocol

class CANProtocol(Protocol):
	"""CAN Protocol Interface
	This class is an interface for defining protocol objects that
	manage CAN frames and allow for the user to create services that
	use a SocketCAN-based socket.
	"""
	def __init__(self):
		super(CANProtocol, self).__init__()
		self.transport = None
		self.socket = None
		
	def doStart(self):
		self.startProtocol()

	async def doStop(self):
		await self.stopProtocol()
		self.transport = None

	def makeConnection(self, transport):
		"""
		Make a connection to a transport and a server.

		This sets the 'transport' attribute of this DatagramProtocol, and calls the
		doStart() callback.
		"""
		self.transport = transport
		self.doStart()

	########################
	# Interface
	########################

	def getFilters(self):
		"""Get a list of CANFilter objects that get applied
		before we bind to the socket.
		"""
		return []

	def startProtocol(self):
		"""
		Called when a transport is connected to this protocol.
		"""
		pass

	def stopProtocol(self):
		"""
		Called when the transport is disconnected.
		"""
		pass

	def frameReceived(self, frame):
		"""
		Called when a CAN Frame that matches our filter is received.

		@param frame CANFrame tuple containing the (data, addr, rtr)
		"""
		pass

	def errorFrameReceived(self, frame):
		"""
		Called when an error CAN frame is received.
		"""
		pass