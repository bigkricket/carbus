#!/bin/bash
#
#  Utility for setting up the CAN netdev devices for
# our application.
#

show_help() {

	echo "Setup the CAN bus device"
	echo ""

	echo "Example:"
	echo " Default to the 'can0' CAN bus device: "
	echo "    $> ifup_can.sh"
	echo " Explicit CAN bus device: "
	echo "    $> ifup_can.sh -i can1"
	echo " Explicit CAN bus device and Bitrate: "
	echo "    $> ifup_can.sh -i can0 -b 250000"

}

ifname="can0"
BITRATE=1000000
RESTARTMS=100

while getopts "i:b:" opt; do
	case "$opt" in
		i)
			ifname=${OPTARG}
			;;
		b)
			BITRATE=${OPTARG}
			;;
		*)
			show_help
			exit 1
	esac
done
shift $((OPTIND-1))

if [ -z "${ifname}" ]; then
	echo "CAN Interface must be non-zero"
	exit 1
fi

echo "CAN Interface: $ifname"


sudo ip link set can0 up type can bitrate 500000 restart-ms 100 listen-only on
