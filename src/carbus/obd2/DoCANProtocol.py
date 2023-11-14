"""Implementation of the OBD2 interface.
Standard guide can be found here:
https://raw.githubusercontent.com/devcoons/iso15765-canbus/master/doc/ISO-15765-2-2016.pdf

File: DoCANProtocol.py
Author: Ruben Perez

Description:
	This file contains the implementation of the ISO15765-2 DoCAN 
	(CAN diagnostic communication) protocol.
	
Definitions:
	N_USData: network layer unacknowledged segmented data transfer service name
	N_ChangeParameter: network layer service name
	N_SDU: network service data unit


Two types of service are defined
.a)   Communication services:
	These services, of which the following are defined, enable the transfer of up 
	to 4 294  967  295  bytes of data
	.1)   N_USData.request: This service is used to request the transfer of data. 
		If necessary, the network layer segments the data
	.2)  N_USData_FF.indication:  This  service  is  used  to  signal  the  beginning  
		of  a  segmented  message  reception to the upper layer
	.3)   N_USData.indication: This service is used to provide received data to 
		the higher layers
	.4)   N_USData.confirm: This service confirms to the higher layers that the 
		requested service has been carried out (successfully or not)
.b) Protocol parameter setting services:These  services,  of  which  the  following  
	are  defined,  enable  the  dynamic  setting  of  protocol parameters
	.1)   N_ChangeParameter.request: This service is used to request the dynamic 
		setting of specific internal parameters
	.2)   N_ChangeParameter.confirm: This service confirms to the upper layer that 
		the request to change a specific protocol has completed (successfully or not).
"""

import logging
import struct
import asyncio
import struct
from collections import deque, namedtuple
from enum import Enum
from ..can.CANProtocol import CANProtocol
from ..can.SocketCAN import CANFilter, CANFrame
from ..tools.bitmask import BM

#####################################################
### Service Data Unit Definitions ###
#####################################################
"""
All network layer services have the same general format. Service primitives are 
written in the form:

service_name.type( 
	parameter A,
	parameter B
	[,parameter C, ...] 
	)

where “service_name” is the name of the service, e.g. N_USData, “type” indicates 
the type of service primitive, and “parameter A, parameter B [,parameter C, ...]” 
are the N_SDU as a list of values passed by the service primitive. The square brackets 
indicate that this part of the parameter list may be empty
"""

class Mtype(Enum):
	"""
	Type: enumeration
	Range: diagnostics, remote diagnostics
	
	Description: The parameter Mtype shall be used to identify the type and range 
	of address information parameters included in a service call. This part of 
	ISO 15765 specifies a range of two values for this parameter. The intention 
	is that users of this part of ISO 15765 can extend the range of values by 
	specifying other types and combinations of address information parameters to 
	be used with the network layer protocol specified in this part of ISO 15765. 
	For each such new range of address information, a new value for the Mtype 
	parameter shall be specified to identify the new address information.
	—   If Mtype =  diagnostics, then the address information N_AI shall consist 
		of the parameters N_SA, N_TA, and N_TAtype.
	—   If Mtype =  remote diagnostics, then the address information N_AI shall 
		consist of the parameters N_SA, N_TA, N_TAtype, and N_AE.
	"""
	Diagnostics = 0x01
	RemoteDiagnostics = 0x02

class N_TAtype:
	"""
	Type: enumeration
	Range: see below
	
	Description: The parameter N_TAtype is an extension to the N_TA parameter. 
	It shall be used to encode the communication model used by the communicating 
	peer entities of the network layer. The following requirements shall be 
	supported.
	—   The network layer protocol shall be capable of carrying out parallel 
	transmission of different messages that are not mapped onto the same N_AI.
	—   Error handling for unexpected PDUs only pertains to messages with the 
	same N_AI.
		— CLASSICAL CAN frames will not cause a CAN FD message to be terminated 
			and vice-versa.
		— This explicitly prevents mixing CAN FD/CLASSICAL CAN frame types in a 
			single message
		
	Physical addressing: (1 to 1 communication) shall be supported for all types 
	of network layer messages

	Functional addressing: (1 to n communication) shall be supported for SingleFrame
	transmission
	"""
	N_TAtypePhysicalCAN = 0x01
	N_TAtypeFunctionalCAN = 0x02
	N_TAtypePhysicalCANFD = 0x03
	N_TAtypeFunctionalCANFD = 0x04
	N_TAtypePhysicalCANEXT = 0x05
	N_TAtypeFunctionalCANEXT = 0x06
	N_TAtypePhysicalCANFDEXT = 0x07
	N_TAtypeFunctionalCANFDEXT = 0x08
	
class N_AI(object):
	"""
	N_AI description:
	These parameters refer to addressing information. As a whole, the N_AI 
	parameters are used to identify the source address (N_SA), the target address 
	(N_TA) of message senders and recipients, as well as the communication model 
	for the message (N_TAtype) and the optional address extension (N_AE).
	
	N_SA, network source address
		Type: 8 bits
		Range: 0x00 to 0xFF
		Description: The N_SA parameter shall be used to encode the sending network 
			layer protocol entity.
			
	N_TA, network target address
		Type: 8 bits
		Range: 0x00 to 0xFF
		Description: The N_TA parameter shall be used to encode one or multiple 
			(depending on the N_TAtype: physical or functional) receiving network 
			layer protocol entities.

	N_TA_TYPE, network target address type
		See the N_TAType class. 

	N_AE, network address extension
		Type: 8 bits
		Range: 0x00 to 0xFF
		Description: The N_AE parameter is used to extend the available address 
		range for large networks and to encode both sending and receiving network 
		layer entities of sub-networks other than the local network where the 
		communication takes place. N_AE is only part of the addressing information 
		if Mtype is set to remote diagnostics.
	"""
	def __init__(self, mtype, n_sa, n_ta, n_ta_type, n_ae=None):
		self.fmt = None
		self.mtype = mtype
		self.n_sa = n_sa
		self.n_ta = n_ta
		self.n_ta_type = n_ta_type
		self.n_ae = n_ae
		self.n_ai = None
	
	def get_format(self):
		if self.mtype == Mtype.Diagnostics:
			self.fmt = "<BBB"
		elif self.mtype == Mtype.RemoteDiagnostics:
			self.fmt = "<BBBB"
		else:
			raise NotImplementedError(f"Invalid Mtype: {self.mtype}")
		return self.fmt
	
	def get_address_information(self):
		"""Construct the byte representation of the Network Address Information.
		"""
		fmt = self.get_format
		if self.mtype == Mtype.Diagnostics:
			self.n_ai = struct.pack(fmt, self.n_sa, self.n_ta, self.n_ta_type)
			return self.n_ai
		elif self.mtype == Mtype.RemoteDiagnostics:
			self.n_ai = struct.pack(fmt, self.n_sa, self.n_ta, self.n_ta_type)
			return self.n_ai
		else:
			raise NotImplementedError(f"Invalid Mtype: {self.mtype}")

#Standard parameter format definitions for the struct library
LENGTH_FMT = "I"
PARAM_VALUE_FMT = "B"

class N_Result(Enum):
	"""
	Type: enumeration
	Range:  N_OK,  N_TIMEOUT_A,  N_TIMEOUT_Bs,  N_TIMEOUT_Cr,  N_WRONG_SN,  
		N_INVALID_FS, N_UNEXP_PDU, N_WFT_OVRN, N_BUFFER_OVFLW, N_ERROR
	Description: This parameter contains the status relating to the outcome of a 
		service execution. If two or more errors are discovered at the same time, 
		then the network layer entity shall use the parameter value found first 
		in this list when indicating the error to the higher layers

	—  N_OK
		This value means that the service execution has been completed successfully; 
		it can be issued to a service user on both the sender and receiver sides.
	—  N_TIMEOUT_A
		This value is issued to the protocol user when the timer N_Ar/N_As has 
		passed its time-out value N_Asmax/N_Armax; it can be issued to service 
		users on both the sender and receiver sides.		
	—  N_TIMEOUT_Bs 
		This value is issued to the service user when the timer N_Bs has passed 
		its time-out value N_Bsmax; it can be issued to the service user on the 
		sender side only.
	—  N_TIMEOUT_CrThis value is issued to the service user when the timer N_Cr 
		has passed its time-out value N_Crmax; it can be issued to the service user 
		on the receiver side only.
	—  N_WRONG_ SN
		This  value  is  issued  to  the  service  user  upon  receipt  of  an  
		unexpected  SequenceNumber  (PCI.SN)  value; it can be issued to the service 
		user on the receiver side only.
	—  N_INVALID_FS
		This  value  is  issued  to  the  service  user  when  an  invalid  or  
		unknown  FlowStatus  value  has  been  received in a FlowControl (FC) N_PDU; 
		it can be issued to the service user on the sender side only.
	—  N_UNEXP_PDU
		This value is issued to the service user upon receipt of an unexpected 
		protocol data unit; it can be issued to the service user on the receiver 
		side only.
	—  N_WFT_OVRN
		This value is issued to the service user when the receiver has transmitted 
		N_WFTmax FlowControl N_PDUs  with  FlowStatus  =  WAIT  in  a  row  and  
		following  this,  it  cannot  meet  the  performance  requirement for the 
		transmission of a FlowControl N_PDU with FlowStatus = ClearToSend. It can 
		be issued to the service user on the receiver side only.
	—  N_BUFFER_OVFLW
		This value is issued to the service user upon receipt of a FlowControl (FC)   
		N_PDU with FlowStatus = OVFLW. It indicates  that  the  buffer  on  the 
		receiver  side  of  a  segmented  message  transmission cannot store the 
		number of bytes specified by the FirstFrame DataLength (FF_DL) parameter  
		in  the  FirstFrame  and  therefore  the  transmission  of  the  segmented  
		message  was  aborted. It can be issued to the service user on the sender 
		side only.
	—  N_ERROR
		This is the general error value. It shall be issued to the service user 
		when an error has been detected by the network layer and no other parameter 
		value can be used to better describe the error. It can be issued to the 
		service user on both the sender and receiver sides.
	"""
	N_OK = 0x01
	N_TIMEOUT_A = 0x02
	N_TIMEOUT_Bs = 0x03
	N_TIMEOUT_Cr = 0x04
	N_WRONG_SN = 0x05
	N_INVALID_FS = 0x06
	N_UNEXP_PDU = 0x07
	N_WFT_OVRN = 0x08
	N_ERROR = 0x09

class Result_ChangeParameter(Enum):
	"""
	Type: enumeration.
	Range: N_OK, N_RX_ON, N_WRONG_PARAMETER, N_WRONG_VALUE
	Description: This parameter contains the status relating to the outcome of a 
		service execution.
	—  N_OK
		This value means that the service execution has been completed successfully; 
		it can be issued to a service user on both the sender and receiver sides.

	—  N_R X_ON
		This value is issued to the service user to indicate that the service did 
		not execute since reception of the message identified by <N_AI> was taking 
		place; it can be issued to the service user on the receiver side only.
	
	—  N_WRONG_PARAMETER
		This  value  is  issued  to  the  service  user  to  indicate  that  the  
		service  did  not  execute  due  to  an  undefined <Parameter>; it can be 
		issued to a service user on both the receiver and sender sides.
	—  N_WRONG_VALUE
		This value is issued to the service user to indicate that the service did 
		not execute due to an out-of-range <Parameter_Value>; it can be issued to 
		a service user on both the receiver and sender sides.
	"""
	N_OK = 0x01
	N_RX_ON = 0x02
	N_WRONG_PARAMETER = 0x03
	N_WRONG_VALUE = 0x04

########################################################
### Transport Protocol ###
########################################################
"""Standard Protocol data unit types

N_PDU format:
	The protocol data unit (N_PDU) enables the transfer of data between the network 
	layer in one node and the network layer in one or more other nodes 
	(peer protocol entities). All N_PDUs consist of three (3) fields, as shown 
	below

There are 4 types of protocol data units:
	
SF N_PDU:
	The SF N_PDU is identified by the SingleFrame protocol control information 
	(SF N_PCI). The SF N_PDU   shall be sent out by the sending network entity and 
	can be received by one or multiple receiving network entities. It shall be sent 
	out to transfer a service data unit that can be transferred via a single service 
	request to the data link layer and to transfer unsegmented messages.

FF N_PDU:
	The FF N_PDU is identified by the FirstFrame protocol control information 
	(FF N_PCI). The FF N_PDU shall be sent out by the sending network entity and 
	received by a unique receiving network entity for the duration of the segmented 
	message transmission. It identifies the first N_PDU of a segmented message 
	transmitted by a network sending entity. The receiving network layer entity 
	shall start assembling the segmented message on receipt of a FF N_PDU.

CF N_PDU:
	The CF N_PDU is identified by the ConsecutiveFrame protocol control information 
	(CF N_PCI). The CF  N_PDU  transfers  segments  (N_Data)  of  the  service  
	data  unit  message  data  (<MessageData>).  All  N_PDUs    transmitted by 
	the sending entity after the FF N_PDU    shall be encoded as CF N_PDUs. The 
	receiving entity shall pass the assembled message to the service user of the 
	network receiving entity after the last CF N_PDU has been received. The CF 
	N_PDU shall be sent out by the sending network entity and received by a unique 
	receiving network entity for the duration of the segmented message transmission.

FC N_PDU:
	The FC N_PDU is identified by the FlowControl protocol control information 
	(FC N_PCI). The FC N_PDU instructs a sending network entity to start, stop or 
	resume transmission of CF N_PDUs. It shall be sent by the receiving network 
	layer entity to the sending network layer entity, when ready to receive more 
	data, after correct reception ofa) an FF N_PDU, orb) the last CF N_PDU of a 
	block of ConsecutiveFrames, if further ConsecutiveFrames need to be sent.The 
	FC N_PDU can also inform a sending network entity to pause transmission of 
	CF N_PDUs during a segmented message transmission or to abort the transmission 
	of a segmented message if the length information (FF_DL) in the FF N_PDU 
	transmitted by the sending entity exceeds the buffer size of the receiving entity.
"""
N_PDU = namedtuple("N_PDU", ["n_ai", "n_pci", "n_data"])
#common bit definitions
N_PCITYPE_MASK = 0xF0
LEN_MASK = 0x0F
LENGTH_OFFSET = 0

class N_PCItype(Enum):
	SF_N_PDU = 0x00
	FF_N_PDU = 0x10
	CF_N_PDU = 0x20
	FC_N_PDU = 0x30

class DoCANProtocol(CANProtocol):

	def __init__(self, node_id=None, n_ai_type=N_TAtype.N_TAtypeFunctionalCAN, min_period=None, timeout=5.0):
		CANProtocol.__init__(self)
		if min_period:
			assert min_period > 0.0, "Invalid MinPeriod: must be positive"
		self._node_id = node_id
		#self._endpoints = self._create_cob_ids(self._node_id)
		self.name = f"can.{node_id}.docan"
		self._data = None
		self._waitDone = None
		self.n_ai_type=n_ai_type
		if self.n_ai_type != N_TAtype.N_TAtypeFunctionalCAN:
			raise Exception(f"Address type not supported: {self.n_ai_type}")

	def set_default_timeout(self, timeout):
		assert timeout > 0.0, "Invalid Timeout - must be positive"
		self._defTO = timeout  # seconds
	
	########################
	# CANProtocol Interface
	########################
	def startProtocol(self):
		#self.state_machine = await self.create()
		#await self.state_machine.enter_state(self.States.idle)
		pass
		
	
	async def stopProtocol(self):
		await self.state_machine.trigger_event(self.state_machine.stop)

	async def frameReceived(self, frame):
		print(frame)

	########################
	# State Machine
	########################	
	@asyncio.coroutine
	def idle(self):
		logging.info(f"{self.name} Waiting for frames.")
	
	@asyncio.coroutine
	def frame_recieved(self, frame):
		pci_type, length = self._get_pci_type(frame)
		#NOTE CANFD can have the payload be greater than 8 bytes but I assume we're using classic CAN
		if pci_type == N_PCItype.SF_N_PDU & length <= 8:
			self.process_single_frame(frame)
		elif pci_type != N_PCItype.SF_N_PDU:
		#@TODO implement logic for other N_PCItypes
			logging.warning(f"N_PCItype not implemented {pci_type}")
			pass	
		else:
			logging.warning(f"Data length too large for N_PCItype {length}")

		
	########################
	# Internal Methods
	########################
	def _get_pci(self, frame):
		pci = frame.data[LENGTH_OFFSET]
		pci_type = pci & N_PCITYPE_MASK	
		length = pci & LEN_MASK
		return pci_type, length
	
	def process_single_frame(self, frame):
		"""Customise this class by overwritting this method	"""
		pass


########################################################
### Communication Service ###
########################################################
"""
N_USData.request:
The service primitive requests transmission of <MessageData> with <Length> bytes
from the sender to the receiver peer entities identified by the address information 
in N_SA, N_TA, N_TAtype [and N_AE] 

N_USData.request( 
	Mtype
	N_SA
	N_TA
	N_TAtype
	[N_AE]
	<MessageData>
	<Length>
	)

Each time the N_USData.request service is called, the network layer shall signal
the completion (or failure) of the message transmission to the service user by 
issuing an N_USData.confirm service call
"""

"""
N_USData.confirm:
The N_USData.confirm service is issued by the network layer. The service primitive 
confirms the completion of an N_USData.request service identified by the address 
information in N_SA, N_TA, N_TAtype [and N_AE]. The parameter <N_Result> provides 
the status of the service request 
N_USData.confirm( 
	Mtype
	N_SA
	N_TA
	N_TAtype
	[N_AE]
	<N_Result>
	)
"""

"""
N_USData_FF.indication:
The N_USData_FF.indication service is issued by the network layer. The service 
primitive indicates to the adjacent upper layer the arrival of a FirstFrame (FF) 
of a segmented message received from a peer protocol entity, identified by the 
address information in N_SA, N_TA, N_TAtype [and N_AE]. This indication shall take 
place upon receipt of the FF of a segmented message.

N_USData_FF.indication( 
	Mtype
	N_SA
	N_TA
	N_TAtype
	[N_AE]
	<Length>
	)
	
The N_USData_FF.indication service shall always be followed by an N_USData.indication 
service call from the network layer, indicating the completion (or failure) of 
message reception.An N_USData_FF.indication service call shall only be issued by 
the network layer if a correct FF message segment has been received.If the network 
layer detects any type of error in an FF, then the message shall be ignored by the 
network layer and no N_USData_FF.indication shall be issued to the adjacent upper 
layer. If the network layer receives an FF with a data length value (FF_DL) that 
is greater than the available receiver buffer size, then this shall be considered 
as an error condition and no N_USData_FF.indication shall be issued to the adjacent 
upper layer.
"""

"""
N_USData.indication:
The N_USData.indication service is issued by the network layer. The service primitive 
indicates <N_Result>  events and delivers <MessageData> with <Length> bytes received 
from a peer protocol entity identified by the address information in N_SA, N_TA,   
N_TAtype [and N_AE] to the adjacent upper layer.The parameters <MessageData> and 
<Length> are valid only if <N_Result> equals N_OK.

N_USData.indication( 
	Mtype
	N_SA
	N_TA
	N_TA
	type[N_AE]
	<MessageData>
	<Length>
	<N_Result>
	)

The N_USData.indication service call is issued after reception of a SingleFrame(SF) 
message or as an indication of the completion (or failure) of a segmented message 
reception.If the network layer detects any type of error in an SF, then the message 
shall be ignored by the network layer and no N_USData.indication shall be issued 
to the adjacent upper layer.
"""

"""
N_ChangeParameters.request:
The service primitive is used to request the change of an internal parameter’s 
value on the local protocol entity. The <Parameter_Value> is assigned to the 
<Parameter>.A parameter change is always possible, except after reception of the 
FF (N_USData_FF.indication) and until the end of reception of the corresponding 
message (N_USData.indication).

N_ChangeParameter.request( 
	Mtype
	N_SA
	N_TA
	N_TAtype
	[N_AE]
	<Parameter>
	<Parameter_Value>
	)

This is an optional service that can be replaced by implementation of fixed parameter 
values.
"""

"""
N_ChangeParameter.confirm:
The service primitive confirms completion of an N_ChangeParameter.confirm service 
applying to a message identified by the address information in N_SA, N_TA, N_TAtype 
[and N_AE].

N_ChangeParameter.confirm( 
	Mtype
	N_SA
	N_TA
	N_TAtype
	[N_AE]
	<Parameter>
	<Result_ChangeParameter>
	)
"""
#########################################################
### Parameter Change Service ###
#########################################################