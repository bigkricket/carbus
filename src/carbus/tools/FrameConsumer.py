"""Frame consumer base class.

File: FrameConsumer.py

Author: Ruben Perez

Description:
	This file contains the implementation of a frame consumer which can be used
	process raw can frames received from the DoCAN protocol.

	This implementation of the CANOpen stack is setup to use the asyncio
python framework. It leverages the SocketCAN interface in the linux
kernel.
"""

import logging
import numbers

import asyncio

from ..obd2.DoCANProtocol import DoCANProtocol, N_TAtype
from ..can.SocketCAN import CANFilter

class InvalidFrameError(ValueError):
	pass

class FrameConsumer(DoCANProtocol):
	"""General purpose frame listener that processes a frame when it is received"""

	def __init__(self, cobIds=None, mask=CANFilter.SFF_MASK, loop=None):
		"""Frameconsumer Constructor
		
		Args:
			cobIds: int or list of ints that indicate the COB IDs of the frames we should
				filter and listen for.
			mask: optional mask for receiving a range of COB IDs.
		"""
		if cobIds is None:
			cobIds = []

		super(FrameConsumer, self).__init__()

		if isinstance(cobIds, numbers.Number):
			self._cobIds = set([cobIds])
		else:
			self._cobIds = set(cobIds)
		
		self._mask = mask
		self.loop = loop

		self.curr_raw_frame = None

	@property
	def cob_ids(self):
		return self._cobIds
	
	def add_cob_id(self, cobId):
		self._cobIds.add(cobId)

	def transform(self, frame):
		"""Customize this class by overwriting this frame.
		
		This converts values into something useful. On an invalid frame, the user
		can rais 'InvalidFrameError
		""" 
		print(frame)
		return frame
	
	#######################
	# CANProtocol Interface
	#######################

	def getFilters(self):
		return [CANFilter(cob, self._mask) for cob in self._cobIds]

	def process_single_frame(self, frame):
		self.cur_raw_frame = frame
		frame = self.transform(frame)	
		self.loop.call_soon(self.transform, frame)