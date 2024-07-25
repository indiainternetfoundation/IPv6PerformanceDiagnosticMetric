import threading
import socket
import platform
from scapy.all import Ether, IPv6
from scapy.all import sniff, send, sendp


def threaded(func):
    def wrapped_func(*args, **kwargs):
        threaded_func = threading.Thread(target=func, args=args, kwargs=kwargs)
        return threaded_func.start()
    return wrapped_func

class NetworkAdaptar:
    ETH_P_ALL = 3
    def __init__(self, iface = "lo", mtu = 1024):
        print(platform.system())

        if platform.system() == "Linux":
            # self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((iface, 0))

        elif (platform.system() == "Darwin") or (platform.system() == "Windows"):
            self.sock = None


        self.listening = False
        self.mtu = mtu

    def __call__(self, ):
        pass

    def send(self, ethernet_frame:Ether):
        if self.sock:
            self.sock.send(ethernet_frame)
        else:
            sendp(ethernet_frame)


    @threaded
    def listen(self, callback, filter = lambda x:x):
        if self.sock:
            self.listening = True
            try:
                while self.listening:
                    data = self.sock.recv(self.mtu) # buffer size is 1024 bytes
                    _packet = Ether(data)
                    if IPv6 in _packet:
                        if filter(_packet):
                            callback(_packet)
            except KeyboardInterrupt:
                self.listening = False
                sys.exit(0)
        else:
            def fltr(_packet):
                if IPv6 in _packet:
                    if filter(_packet):
                        callback(_packet)
            sniff(prn = lambda packet: fltr(packet))

