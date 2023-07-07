"""Contains python ifreq implementation

File: IfReq.py

Python implemenation of the interface request structure used for socket ioctl's.

More documentation can be found here: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if.h
"""
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
sa_family_t = c_uint16

ADDR_LEN = 14

class IfMap(Structure):
	#This class represents a C-compatible structure for network interface mapping.	
	_fields_ = [
		("mem_start", c_ulong),# used to store memory addresses.
		("mem_end", c_ulong),#This field is used to store the end address of the memory range.
		("base_addr", c_ushort),#used to store base addresses.
		("irq", c_uint8),#used for storing interrupt request numbers.
		("dma", c_uint8),#This field is used to store DMA (Direct Memory Access) channel numbers.
		("port", c_uint8),#This field is typically used to store port numbers.
	]

class SockAddr(Structure):
	#This class represents a C-compatible structure for socket addresses.
	_fields_ = [
		("sa_family", sa_family_t),
		("sa_addr", c_char * ADDR_LEN),# c_char * ADDR_LEN represents an array of characters (c_char) with a length of ADDR_LEN. This field is used to store the address information.
	]


class IfMap(Structure):
	"""This class represents a C-compatible structure for network interface mapping.	

	struct ifmap {
		unsigned long mem_start;
		unsigned long mem_end;
		unsigned short base_addr; 
		unsigned char irq;
		unsigned char dma;
		unsigned char port;
		/* 3 bytes spare */
	};
		"""
	_fields_ = [
		("mem_start", c_ulong),# used to store memory addresses.
		("mem_end", c_ulong),#This field is used to store the end address of the memory range.
		("base_addr", c_ushort),#used to store base addresses.
		("irq", c_uint8),#used for storing interrupt request numbers.
		("dma", c_uint8),#This field is used to store DMA (Direct Memory Access) channel numbers.
		("port", c_uint8),#This field is typically used to store port numbers.
	]

IFNAMSIZ = 16 #This constant represents the maximum length of a network interface name. Network interface names are used to identify and refer to individual network interfaces, such as eth0 or wlan0.
SIOCGIFINDEX = 0x8933#This constant represents a socket IOCTL (IO Control) command for retrieving the index of a network interface. IOCTL commands are used to control and retrieve information from devices and interfaces in operating systems.
SIOCGSTAMP = 0x8906#his constant represents a socket IOCTL command for retrieving the timestamp of the last received packet on a network interface. It is often used for monitoring network activity and measuring network latency.


class IfReqAddr(Union):
	"""The ifreq_addr union allows flexible access to different fields of the structure based on the specific operation or attribute being accessed or modified. It provides a way to interact with network interface attributes using the appropriate field and data type for the given context.
	"""
	_fields_ = [
		("ifr_addr", SockAddr),
		("ifr_dstaddr", SockAddr),
		("ifr_broadaddr", SockAddr),
		("ifr_netmask", SockAddr),
		("ifr_hwaddr", SockAddr),
		("ifr_flags", c_short),
		("ifr_ifindex", c_int),
		("ifr_metric", c_int),
		("ifr_mtu", c_int),
		("ifr_map", IfMap),
		("ifr_slave", c_char * IFNAMSIZ),
		("ifr_newname", c_char * IFNAMSIZ),
		("ifr_data", c_char_p),
	]


class IfReq(Structure):
	"""Interface request structure used for socket ioctl's

	/* for compatibility with glibc net/if.h */
	#if __UAPI_DEF_IF_IFREQ
	struct ifreq {
	#define IFHWADDRLEN	6
		union
		{
			char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
		} ifr_ifrn;

		union {
			struct	sockaddr ifru_addr;
			struct	sockaddr ifru_dstaddr;
			struct	sockaddr ifru_broadaddr;
			struct	sockaddr ifru_netmask;
			struct  sockaddr ifru_hwaddr;
			short	ifru_flags;
			int	ifru_ivalue;
			int	ifru_mtu;
			struct  ifmap ifru_map;
			char	ifru_slave[IFNAMSIZ];	/* Just fits the size */
			char	ifru_newname[IFNAMSIZ];
			void __user *	ifru_data;
			struct	if_settings ifru_settings;
		} ifr_ifru;
	};
	"""
	_anonymous_ = ("_addr",)
	_fields_ = [
		("ifr_name", c_char * IFNAMSIZ),
		("_addr", IfReqAddr),  # anonymous in C
	]