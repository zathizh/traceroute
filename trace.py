import socket, os, struct, sys, optparse
from ctypes import *

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ICMP_HEADER_LEN = 12

ETH_P_IP = 0x0800

version = 4
ihl = 5
tos = 0
t_len = 0
ip_id = 54320
f_off = 0
h_checksum = 0
s_addr = socket.inet_aton ("192.168.1.33")
ip_ihl_ver = (version << 4) + ihl

icmp_type = 8
icmp_code = 0
icmp_checksum = 0
icmp_id = 1
icmp_seq = 0
## icmp_data = 0

#recvsock= socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
recvsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sendsock= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

recvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#recvsock.bind(('eth0', 0))
recvsock.bind(('ens33', 0))

sendsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
recvsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# IP header
class _ICMP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32),
	("type", c_ubyte),
	("code", c_ubyte),
	("icmp_check", c_ushort),
	("icmp_id", c_ushort),
	("seq", c_ushort),
	("data", c_uint32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

def informations(i, icmp_response):
	print(i),
	print("\t"),
	print(icmp_response.dst_address)
    

def pinger(d_addr, ttl=256, proto=1):
	##d_addr = socket.inet_aton ( dest )
	for i in range(1, ttl):
                p_id = ip_id + 1
                icmp_seq = icmp_seq + 1
		icmp_request = struct.pack('!BBHHHBBH4s4sBBHHH', ip_ihl_ver, tos, t_len, ip_id, f_off, ttl, proto,  h_checksum, s_addr, d_addr, icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
		sendsock.sendto(icmp_request, (d_addr , 0 ))

		data = recvsock.recvfrom(65565)[0]
		icmp_response = _ICMP(data[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN])
		
		print(i),
		print("\t"),
		print(icmp_response.dst_address),
		print("\t"),

def main():
        parser = optparse.OptionParser("usage %prog - t [ttl] -p [protocol] -d [destination address]")
        parser.add_option("-t", dest="ttl", type="int", help="specify ttl")
	parser.add_option("-p", dest="proto", type="int", help="specify protocol")
	parser.add_option("-d", dest="dest", type="string", help="specify destination")
        (options, args) = parser.parse_args()
	ttl = options.ttl
	proto = options.proto
	dest = options.dest

	if (dest is not None and (type(ttl) is int or ttl is None) and (type(proto) is int or proto is None)):
		if (ttl and proto):
			pinger(dest, ttl+1, proto)
		elif (ttl):
			pinger(dest, ttl+1)
		else:
			pinger(dest)

if __name__ == '__main__':
	main()
