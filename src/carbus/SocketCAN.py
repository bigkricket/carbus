"""Contains python SocketCan implementation

File: SocketCan.py

python wrapper for: https://www.kernel.org/doc/html/latest/networking/can.html 

definitions for CAN network layer can be grabbed from: https://github.com/linux-can/can-utils/blob/master/include/linux/can.h

Description:
	This file defines some classes to allow python to work with CAN sockets
"""

import array
import operator
import os
import socket
import subprocess as sp
from .IfReq import IfReq, SIOCGIFINDEX, SIOCGSTAMP
from collections import namedtuple

from ctypes import (#a Python library for interfacing with C code
	CDLL,#This class represents a dynamic link library (DLL) and provides access to its functions. You can use it to load and interact with C functions from shared libraries.
	POINTER,#This class is used to create a pointer type that can be used to access and manipulate memory in C-compatible data structures.
	Structure,#This class is used to define C-compatible structures. It allows you to specify the layout and types of fields within the structure.
	Union,#This class is used to define C-compatible unions. Similar to structures, unions allow you to specify the layout and types of fields. However, unions only allocate memory for the largest field and allow accessing any of the fields.
	byref,#This function is used to create a pointer to a given object. It is often used when calling C functions that expect pointers as arguments.
	c_char,
	c_char_p,
	c_int,
	c_long,
	c_short,
	c_uint8,
	c_uint16,
	c_uint32,
	c_uint64,
	c_ulong,
	c_ushort,
	c_void_p,
	pointer,#This function is used to create a pointer object that points to a given object. It is similar to byref but returns a pointer object instead of a pointer value.
	sizeof,#This function returns the size in bytes of a given object or type. It can be used to determine the memory size of C-compatible structures or types.
)

from ctypes.util import find_library
from enum import Enum, IntEnum
from functools import reduce


#particular protocols of the protocol family PF_CAN defined in can.h
PF_CAN_definitions = [
	("PF_CAN", 29),
	("CAN_RAW", 1),
	("CAN_BCM", 2),
	("CAN_TP16", 3),
	("CAN_TP20", 4),
	("CAN_MCNET", 5),
	("CAN_ISOTP", 6),
	("CAN_J1939", 7),
	("CAN_NPROTO",8),
	("SOL_CAN_BASE",100),
]

#check to make sure  that socket is configured correctly 
for name, val in PF_CAN_definitions:
	try:
		getattr(socket, name)
	except AttributeError:
		setattr(socket, name, val)

sa_family_t = c_uint16 #in can.h this is defined as an unsigned short

canid_t = c_uint32
can_err_mask_t = c_uint32

class CanId(Structure):
	_fields_=[
		("rx_id", c_uint32),
		("tx_id", c_uint32)
	]

class J1939Address(Structure):
	_fields_ = [
		("name", c_uint64),
		("pgn",c_uint32),
		("addr", c_uint8)
	]

class CanAddr(Union):
	_fields_ = [
		("tp", CanId),
		("j1939", J1939Address)
	]

class SockAddrCan(Structure):
	_fields_=[
		("can_family", sa_family_t),
		("can_ifindex", c_int),
		("can_addr", CanAddr)
	]

class TimeVal(Structure):
	_fields_ = [
		("tv_sec", c_long),
		("tv_usec", c_long),
	]

# See "Linux/can.h"
FRAME_LEN = 8 #length of data sent out in CAN message
CAN_EFF_FLAG = 0x80000000 #(CAN extended farme format flag) used to indicate a 29-bit ID rather than an 11-bit ID
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000

CAN_SFF_MASK = 0x7FF #(CAN Standard frame format mask)
CAN_EFF_MASK = 0x1FFFFFFF #(CAN extended frame format mask) used to filter/match extended CAN ids
CAN_ERR_MASK = 0x1FFFFFFF

CAN_INV_FILTER = 0x20000000
CAN_RAW_FILTER_MAX = 512

class CanFrame(Structure):
	"""Based off of the can_frame struct in the kernel documentation:

	struct can_frame {
		canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
		union {
				/* CAN frame payload length in byte (0 .. CAN_MAX_DLEN)
				 * was previously named can_dlc so we need to carry that
				 * name for legacy support
				 */
				__u8 len;
				__u8 can_dlc; /* deprecated */
		};
		__u8    __pad;   /* padding */
		__u8    __res0;  /* reserved / padding */
		__u8    len8_dlc; /* optional DLC for 8 byte payload length (9 .. 15) */
		__u8    data[8] __attribute__((aligned(8)));
	};
	"""
	_fields_ = [
		("can_id", c_uint32),
		("len", c_uint8),
		("__pad", c_uint8),
		("__res0", c_uint8),
		("len8_dlc", c_uint8),
		("data", c_uint8 * FRAME_LEN)
	]

	def load(self, data, addr, rtr=False, ext=False):
		"""Load a can frame structure with the necessary data for a frame.

		Args:
			data (str): containing up to 8 bytes. Message will be truncated if\
				more than 8 bytes is provided.
			addr: CAN Node address that this data is destined for.
			rtr: set the remote transmission request bit.
			ext: use the extended address space.
		"""
		if ext:
			#if the frame is using an extended cob-id flag it here. 
			canId = addr & CAN_EFF_MASK
			canId |= CAN_EFF_FLAG
		else:
			canId = addr & CAN_SFF_MASK
		
		if rtr:
			#not really used anymore but nice to have anyways
			canId |= CAN_RTR_FLAG
		
		self.can_id = canId
		self.load_data(data)
	
	def load_data(self, data):
		if len(data) > FRAME_LEN:
			raise RuntimeError(
				f"CAN Frame too large: {len(data)} > {FRAME_LEN}"
			)
		
		self.len = len(data)
		for i in range(len(data)):
			self.data[i] = data[i]
	
	def __str__(self):
		data = [int(self.data[i]) for i in range(self.len)]
		return "<can_frame:struct id={} data={} len={}>".format(
			self.can_id, data, self.len
		)

	def __repr__(self):
		return str(self)
	
class can_filter(Structure):
	_fields_ = [
		("can_id", c_uint32),
		("can_mask", c_uint32),
	]

########################
# CAN Error Class Definitions
########################
# See "linux/can/error.h"
class CANErrorClass(IntEnum):
	TransmitTimeout = 0x00000001
	LostArbitration = 0x00000002
	ControllerError = 0x00000004
	ProtocolViolation = 0x00000008
	TransceiverStatus = 0x00000010
	NoAcknowledge = 0x00000020
	BusOff = 0x00000040
	BusError = 0x00000080
	ControllerRestarted = 0x00000100


LOSTARB_OFFSET = 0
CONTROLLER_STAT_OFFSET = 1
PROTO_TYPE_OFFSET = 2
PROTO_LOC_OFFSET = 3
TRANSCEIVER_OFFSET = 4


class CANControllerStatus(Enum):
	Unspecified = 0x00
	RxBufferOverflow = 0x01
	TxBufferOverflow = 0x02
	RxWarningLevel = 0x04
	TxWarningLevel = 0x08
	RxPassive = 0x10
	TxPassive = 0x20
	RecoveredToError = 0x40


class CANProtoStatusType(Enum):
	Unspecified = 0x00
	SingleBitError = 0x01
	FrameFormatError = 0x02
	BitStuffingError = 0x04
	DominantBitError = 0x08
	RecessiveBitError = 0x10
	BusOverload = 0x20
	ActiveError = 0x40
	TransmitError = 0x80


class CANProtoStatusLoc(Enum):
	Unspecified = 0x00
	StartOfFrame = 0x03
	LocID28_21 = 0x02
	LocID20_18 = 0x06
	SubRTR = 0x04
	IdentExt = 0x05
	LocID17_13 = 0x07
	LocID12_05 = 0x0F
	LocId04_00 = 0x0E
	RTR = 0x0C
	RES1 = 0x0D
	RES0 = 0x09
	DLC = 0x0B
	DATA = 0x0A
	CRC_SEQ = 0x08
	CRC_DEL = 0x18
	ACK = 0x19
	ACK_DEL = 0x1B
	EOF = 0x1A
	INTERM = 0x12

	UnknownError = 0x100  # out of range of 8-bit value


class CANTransceiverStatus(Enum):
	Unspecified = 0x00
	CANH_NO_WIRE = 0x04
	CANH_SHORT_TO_BAT = 0x05
	CANH_SHORT_TO_VCC = 0x06
	CANH_SHORT_TO_GND = 0x07
	CANL_NO_WIRE = 0x40
	CANL_SHORT_TO_BAT = 0x50
	CANL_SHORT_TO_VCC = 0x60
	CANL_SHORT_TO_GND = 0x70
	CANL_SHORT_CANH = 0x80

	UnknownError = 0x100  # out of range of 8-bit value

################################
# Libc Interface Definitions
################################

# LIBC_NAME = "libc.so.6"
LIBC_NAME = find_library("c")
libc = CDLL(LIBC_NAME)

# This is kind of a hack to get the errno value. I was
#  having an issue where the get_errno() method was not
#  returning the appropriate value.
get_errno_loc = libc.__errno_location
get_errno_loc.restype = POINTER(c_int)


def errcheck(ret, func, args):
	"""Method that checks the errno value for libc methods.

	This is necessary because otherwise, some other libc function gets called
	before we can get the value of errno and we lose it. Also provides
	a convenient method to checking the return value and converting
	to an exception.
	"""
	if ret == -1:
		e = get_errno_loc()[0]
		raise OSError(
			"CAN: func={} errno={} errstr={} args={}".format(
				func.__name__, e, os.strerror(e), args
			)
		)
	return ret


# Setup error check on used methods
# @note - if you add any more methods - you should add them here.
addErrCheckMethods = [
	libc.read,
	libc.write,
	libc.bind,
	libc.connect,
	libc.getsockopt,
	libc.setsockopt,
	libc.ioctl,
]
for func in addErrCheckMethods:
	func.errcheck = errcheck

libc.getsockopt.argtypes = [
	c_int,  # int sockfd
	c_int,  # int level
	c_int,  # int optname
	c_void_p,  # void *optval
	POINTER(c_uint32),  # socklen_t *optlen
]
libc.setsockopt.argtypes = [
	c_int,  # int sockfd
	c_int,  # int level
	c_int,  # int optname
	c_void_p,  # void *optval
	c_uint32,  # socklen_t optlen
]

class CANFrame(object):
	def __init__(self, data, addr, rtr, ts=None):
		self.data = data
		self.addr = addr
		self.rtr = rtr
		self.ts = ts
	
	def __eq__(self, other):
		tests = (
			self.data == other.data,
			self.addr == other.addr,
			self.rtr == other.rtr,
			# note we are not comparing ts here
		)
		return all(tests)
	
	def __repr__(self):
		return "CANFrame: ts:{} addr:{} rtr:{} data:{}".format(
			self.ts, self.addr, self.rtr, self.data
		)

CANError = namedtuple(
	"CANError",
	("flags", "position", "ctl_flags", "proto_type", "proto_loc", "trans_error"),
)

class CANAddress(Enum):
	Standard = 1
	Extended = 2
	Both = 3

class CANFilter(object):
	"""Helper class for implementing filtering on the CAN bus interface."""
	SFF_MASK = CAN_SFF_MASK
	EFF_MASK = CAN_EFF_MASK

	def __init__(self, can_id, mask, exclusive=CANAddress.Both, invert=False):
		self.can_id = can_id
		self.mask = mask
		self.exclusive = exclusive
		self.invert = invert

	def __eq__(self, other):
		return self.__dict__ == other.__dict__
	
	def __ne__(self, other):
		return not (self == other)
	
	def __repr__(self):
		return "CANFilter(can_id=0x{:x},mask=0x{:x},exclusive={},invert={})".format(
			self.can_id, self.mask, self.exclusive, self.invert
		)
	
class CANInterfaceUtils(object):
	"""Base class containing utility methods for working with CAN sockets."""

	@staticmethod
	def get_if_nametoindex(name):
		"""Invoke `if_nametoindex` to get the ifindex value of a netdev ifname directly.

		Args:
			name (str): ifname for the netdev we are interested in.
				Unicode strings will not work.

		Returns:
			int ifindex
		"""
		val = libc.if_nametoindex(name)
		if val == 0:
			raise ValueError("Invalid IfIndex '{}' for IfName '{}'".format(val, name))
		return val

	@staticmethod
	def list(f=None):
		"""Get the available vcan interfaces.

		Called with default argument it returns both physical and virtual
		interfaces. Use
		:func:`list_physical` or :func:`list_virtual` to get the list of
		interfaces of particular kind.
		"""
		return sorted(filter(f, os.listdir("/sys/class/net")))

	@staticmethod
	def list_physical(f=None):
		"""Enumerate the available physical CAN interfaces."""
		ifaces = SocketCAN.list(lambda name: name.startswith("can"))
		ifaces.extend(SocketCAN.list(lambda name: name.startswith("rcan")))
		return list(filter(f, ifaces))

	@staticmethod
	def list_virtual(f=None):
		"""Enumerate the available virtual CAN interfaces."""
		return list(filter(f, SocketCAN.list(lambda name: name.startswith("vcan"))))

	@staticmethod
	def is_up(ifname):
		"""Check if the CAN interface with this name is UP.

		Args:
			ifname: inteface name like `vcan0`

		Returns:
			bool
		"""
		cmd = "ip link show {} | grep -c UP".format(ifname)
		try:
			ret = sp.check_output(cmd, shell=True)
			return int(ret) > 0
		except:
			return False

	@staticmethod
	def add_interface_arg(parser, def_ifname="can0"):
		parser.add_argument(
			"-i",
			"--interface",
			default=def_ifname,
			help="Select the SocketCAN interface to bind to",
		)

class CANBase(socket.socket):
	"""Base class for CAN socket objects."""

	def __init__(self, *args, **kwargs):
		socket.socket.__init__(self, *args, **kwargs)

	def _get_ifindex(self, ifname):
		"""Get the interface index by name.

		Args:
			ifname: name of the netdev interface, such as 'can0' or 'vcan1'

		Returns:
			int indicating the interface index.
		"""
		ifr = IfReq(ifname.encode())
		fd = c_int(self.fileno())
		request = c_ulong(SIOCGIFINDEX)
		libc.ioctl(fd, request, byref(ifr))

		return ifr.ifr_ifindex

class SocketCAN(CANBase, CANInterfaceUtils):
	"""SocketCAN is a netdev interface in the linux kernel for reading CAN bus messages.

	This class inherits from the socket class and
	adds the necessary functionality to open CAN protocol sockets.
	Most methods will raise an exception on error.
	"""

	def __init__(self):
		CANBase.__init__(self, socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
		self.ifindex = None

	def bind(self, ifname):
		"""Bind this CAN socket to a particular CAN interface by name.

		Example names would be `can0` or `vcan1`.
		"""
		ifindex = self._get_ifindex(ifname)
		addr = SockAddrCan(socket.AF_CAN, ifindex)

		fd = self.fileno()
		numBytes = sizeof(SockAddrCan)
		libc.bind(fd, byref(addr), numBytes)
		self.ifindex = ifindex

	def write(self, data, addr, rtr=False, ext=False):
		"""Write one CAN data frame on this CAN interface socket.

		Args:
			data (str): containing up to 8 bytes. Message will be
				truncated if more than 8 bytes is provided.
			addr: CAN Node address that this data is destined for.
			rtr: set the remote transmission request bit.
			ext: use the extended address space.
		"""
		if addr is None:
			raise ValueError("Invalid Address: {}".format(addr))

		frame = CANFrame()
		frame.load(data, addr, rtr, ext)

		fd = self.fileno()
		numBytes = sizeof(frame)
		ret = libc.write(fd, byref(frame), numBytes)
		if ret != numBytes:
			msg = "Invalid Write Count: {} != {}".format(ret, numBytes)
			raise RuntimeError(msg)

	def read(self):
		"""Read one CAN frame from the socket.

		Returns:
			CANFrame object containing the data from the frame.
		"""
		fd = self.fileno()
		frame = CANFrame()
		numBytes = sizeof(frame)
		ret = libc.read(fd, byref(frame), numBytes)
		if ret != numBytes:
			msg = "Invalid Read Count: {} != {}".format(ret, numBytes)
			raise RuntimeError(msg)

		addr = frame.can_id
		if addr & CAN_ERR_FLAG:
			return self._handle_error(frame)

		if addr & CAN_EFF_FLAG:
			addr &= CAN_EFF_MASK
		else:
			addr &= CAN_SFF_MASK

		rtr = (frame.can_id & CAN_RTR_FLAG) > 0
		buf = array.array("B", frame.data[: frame.len]).tobytes()
		return CANFrame(buf, addr, rtr, self.get_timestamp())

	def get_timestamp(self):
		"""Must be called directly after calling the read of a frame.

		Returns:
			posix timestamp
		"""
		val = TimeVal()
		fd = c_int(self.fileno())
		request = c_ulong(SIOCGSTAMP)
		libc.ioctl(fd, request, byref(val))

		ret = float(val.tv_sec)
		ret += float(val.tv_usec) / 1000000.0
		return ret

	def set_can_filters(self, filters):
		"""Set the filtering on CAN id.

		Args:
			filters: list of `CANFilter` objects containing the filters that we
				want to apply to our socket.
		"""
		if len(filters) > CAN_RAW_FILTER_MAX:
			raise ValueError(
				"CAN[{}]: Too Many Filters: {} > {}".format(
					self.fileno(), len(filters), CAN_RAW_FILTER_MAX
				)
			)

		rfilterType = can_filter * len(filters)
		rfilters = rfilterType()

		for i, filt in enumerate(filters):
			rfilters[i].can_id = filt.can_id
			rfilters[i].can_mask = filt.mask
			if filt.invert:
				rfilters[i].can_id |= CAN_INV_FILTER

			if filt.exclusive != CANAddress.Both:
				rfilters[i].can_mask |= CAN_EFF_FLAG | CAN_RTR_FLAG
				if filt.exclusive == CANAddress.Extended:
					rfilters[i].can_id |= CAN_EFF_FLAG

		fd = self.fileno()
		libc.setsockopt(
			fd,
			socket.SOL_CAN_RAW,
			socket.CAN_RAW_FILTER,
			byref(rfilters),
			sizeof(rfilters),
		)

	def get_can_filters(self):
		"""Returns the number of sockets."""
		fd = self.fileno()
		rfilterType = can_filter * CAN_RAW_FILTER_MAX
		rfilters = rfilterType()
		lenVal = c_uint32(CAN_RAW_FILTER_MAX)
		libc.getsockopt(
			fd,
			socket.SOL_CAN_RAW,
			socket.CAN_RAW_FILTER,
			byref(rfilters[0]),
			byref(lenVal),
		)

		retLen = lenVal.value
		numFilts = retLen // sizeof(can_filter)

		ret = []
		for i in range(numFilts):
			rfilt = rfilters[i]
			canId = rfilt.can_id
			mask = rfilt.can_mask

			invFlag = (canId & CAN_INV_FILTER) > 0
			canId &= ~CAN_INV_FILTER

			EXC_GROUP = CAN_EFF_FLAG | CAN_RTR_FLAG
			exclusive = CANAddress.Both
			if (mask & EXC_GROUP) == EXC_GROUP:
				# Exclusively either standard or extended
				ext = canId & CAN_EFF_FLAG
				canId &= ~(CAN_EFF_FLAG)
				exclusive = CANAddress.Extended if ext else CANAddress.Standard
			mask &= ~EXC_GROUP
			filt = CANFilter(canId, mask, exclusive, invFlag)
			ret.append(filt)
		return ret

	def set_error_mask(self, flags=frozenset(CANErrorClass)):
		"""Set the current mask for allowing the kernel to generate different types of errors.

		Args:
			flags: list or set of CANErrorClass values indicating
				the allowed error types.
		"""
		flag_sum = reduce(operator.or_, map(int, flags), 0)
		mask = can_err_mask_t(flag_sum)
		fd = self.fileno()
		libc.setsockopt(
			fd, socket.SOL_CAN_RAW, socket.CAN_RAW_ERR_FILTER, byref(mask), sizeof(mask)
		)

	def get_error_mask(self):
		"""Retrieve a set of enabled error mask flags in use by this socket.

		Returns:
			set of CANErrorClass flags.
		"""
		mask = can_err_mask_t()
		lenVal = c_uint32(sizeof(mask))
		fd = self.fileno()

		libc.getsockopt(
			fd,
			socket.SOL_CAN_RAW,
			socket.CAN_RAW_ERR_FILTER,
			byref(mask),
			byref(lenVal),
		)

		mask = mask.value
		ret = set([x for x in CANErrorClass if (x.value & mask) > 0])
		return ret

	def set_loopback(self, enable):
		"""Enable/Disable the loopback of capability on the socket.

		This is primarily useful in multi-user cases where we want to silence
		packets from another user.
		"""
		val = c_int(1 if enable else 0)
		fd = self.fileno()
		libc.setsockopt(
			fd, socket.SOL_CAN_RAW, socket.CAN_RAW_LOOPBACK, byref(val), sizeof(val)
		)

	def get_loopback(self):
		"""Get the state of the local loopback.

		If enabled, the kernel will allow this process to read any message sent
		by other processes that are also generating CAN messages (by default
		our own are filtered out, see `get/set_receive_own` below).
		Default is enabled.

		Returns:
			bool
		"""
		val = c_int()
		lenVal = c_uint32(sizeof(val))

		fd = self.fileno()
		libc.getsockopt(
			fd, socket.SOL_CAN_RAW, socket.CAN_RAW_LOOPBACK, byref(val), byref(lenVal)
		)

		val = val.value

		return val > 0

	def set_receive_own(self, enable):
		"""By default the linux kernel will not loopback CAN messages.

		This flag can enable/disable that feature as necessary.
		You probably don't want to use this unless you absolutely know what you
		are doing.
		"""
		val = c_int(1 if enable else 0)
		fd = self.fileno()
		libc.setsockopt(
			fd,
			socket.SOL_CAN_RAW,
			socket.CAN_RAW_RECV_OWN_MSGS,
			pointer(val),
			sizeof(val),
		)

	def get_receive_own(self):
		"""Query socket to see if the kernel will loopback messages sent out.

		By default, this is disabled.

		Returns:
			bool
		"""
		val = c_int()
		lenVal = c_uint32(sizeof(val))

		fd = self.fileno()
		libc.getsockopt(
			fd,
			socket.SOL_CAN_RAW,
			socket.CAN_RAW_RECV_OWN_MSGS,
			pointer(val),
			byref(lenVal),
		)

		val = val.value

		return val > 0

	def _handle_error(self, frame):
		"""Error handler for CAN socket.

		The CAN socket interface can send back special messages with error data
		encoded in them. @see `linux/can/error.h` for more information.

		Args:
			frame: CAN message frame of type `can_frame`

		Returns:
			CANError tuple with error information extracted.
		"""
		mask = frame.can_id & CAN_ERR_MASK
		flags = set([x for x in CANErrorClass if (x.value & mask) > 0])

		position = None
		ctlFlags = set([])
		protoType = set([])
		protoLoc = None
		transError = None
		if CANErrorClass.LostArbitration in flags:
			position = int(frame.data[LOSTARB_OFFSET])

		elif CANErrorClass.ControllerError in flags:
			ctlVal = frame.data[CONTROLLER_STAT_OFFSET]
			ctlFlags = set([x for x in CANControllerStatus if (x.value & ctlVal)])

		elif CANErrorClass.ProtocolViolation in flags:
			typeVal = int(frame.data[PROTO_TYPE_OFFSET])
			protoType = set([x for x in CANProtoStatusType if (x.value & typeVal)])
			try:
				protoLoc = frame.data[PROTO_LOC_OFFSET]
			except Exception:
				protoLoc = CANProtoStatusLoc.Unknown

		elif CANErrorClass.TransceiverStatus in flags:
			transVal = frame.data[TRANSCEIVER_OFFSET]
			try:
				transError = CANTransceiverStatus(transVal)
			except Exception:
				transError = CANTransceiverStatus.Unknown

		ret = CANError(flags, position, ctlFlags, protoType, protoLoc, transError)
		return ret