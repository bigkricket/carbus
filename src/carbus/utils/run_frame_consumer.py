import logging
import asyncio
#from ..tools.FrameConsumer import FrameConsumer
#from ..can.CANPort import CANPort
from carbus.tools.FrameConsumer import FrameConsumer
from carbus.can.CANPort import CANPort, CANPortCollection

def main():
    loop = asyncio.get_event_loop()
    fc = FrameConsumer(cobIds=0x1d0, loop=loop)
    CANobject = CANPortCollection('vcan0')
    CANobject.add_socket(fc)
    CANobject.startListening()
    fc.startProtocol()
    loop.run_forever()
    while(True):
        pass

if __name__ == '__main__':
    main()