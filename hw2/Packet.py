# -*- coding:utf-8 -*-


import struct
import socket


class Packet(object):
    def __init__(self, _header, buf):
        hdr_fmt = '>' + ''.join([x[1] for x in _header])  # '>' means the binary data is big-endian
        hdr_fields = [x[0] for x in _header]
        self.__hdr_len__ = struct.calcsize(hdr_fmt)
        i = 0
        for hdr_val in struct.unpack(hdr_fmt, buf[:self.__hdr_len__]):
            setattr(self, hdr_fields[i], hdr_val)  # add header's field-keys to class's attributes
            i += 1

        self.data = buf[self.__hdr_len__:]


# class of Ethernet
# some Ethernet_II payload types
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
_eth_header = (
    ('dst', '6s'),
    ('src', '6s'),
    ('type', 'H')
)


class Ethernet(Packet):
    def __init__(self, buf):
        super(Ethernet, self).__init__(_eth_header, buf)


# class of IP
# some IP protocol
IP_PROTO_TCP = 6  # TCP
IP_PROTO_UDP = 17  # UDP
_ip_header = (
    ('_v_hl', 'B'),  # ip header length(unit: 4 bytes)
    ('type_of_service', 'B'),
    ('len', 'H'),
    ('id', 'H', 0),
    ('flags_offset', 'H'),
    ('ttl', 'B'),
    ('protocol', 'B'),
    ('checksum', 'H'),
    ('_src', '4s'),
    ('_dst', '4s')
)


class IP(Packet):
    def __init__(self, buf):
        super(IP, self).__init__(_ip_header, buf)
        offload = ((self._v_hl & 0xf) << 2) - self.__hdr_len__
        if self.len:
            self.data = buf[self.__hdr_len__ + offload: self.len]
        else:  # might be TCP segmentation offload
            self.data = buf[self.__hdr_len__ + offload:]
        self.src = socket.inet_ntoa(self._src)
        self.dst = socket.inet_ntoa(self._dst)


# class of TCP
# some TCP control flags
TH_FIN = 0x01  # end of data
TH_SYN = 0x02  # synchronize sequence numbers
TH_ACK = 0x10  # acknowledgment number set
TH_PSH = 0X08
# some TCP options
TCP_OPT_MSS = 2  # maximum segment size, len 4
TCP_OPT_WSCALE = 3  # window scale factor, len 3
TCP_OPT_TIMESTAMP = 8  # timestamp, len 10
_tcp_header = (
    ('src_port', 'H'),
    ('dst_port', 'H'),
    ('seq', 'I'),
    ('ack', 'I'),
    ('_offset', 'B'),
    ('flags', 'B'),
    ('win_size', 'H'),
    ('checksum', 'H'),
    ('urgent_ptr', 'H')
)


def parse_opts(buf):
    opts = {}
    while buf:
        o = buf[0]
        if o <= 1:      # EOL or NOP: only has 1 byte of type field and no len/val field
            buf = buf[1:]
        else:
            len = buf[1]    # includes type, len and info
            d, buf = buf[2:len], buf[len:]
            opts[o] = d
    return opts


class TCP(Packet):
    def __init__(self, buf):
        super(TCP, self).__init__(_tcp_header, buf)
        offload = ((self._offset >> 4) << 2) - self.__hdr_len__
        self.data = buf[self.__hdr_len__ + offload:]

        self.opts = parse_opts(buf[self.__hdr_len__:self.__hdr_len__ + offload])
        self.win_scale = None   # range 0-14
        self.tsval = None   # Timestamp Value
        self.tsecr = None   # Timestamp Echo Reply
        self.MSS = None     # Maximum Segment Size
        self.src_ip = None
        self.dst_ip = None
        self.time = None

        if TCP_OPT_WSCALE in self.opts.keys():
            self.win_scale = int.from_bytes(self.opts[TCP_OPT_WSCALE], "big")
        if TCP_OPT_TIMESTAMP in self.opts.keys():
            ts_buf = self.opts[TCP_OPT_TIMESTAMP]
            self.tsval = int.from_bytes(ts_buf[0:4], "big")
            self.tsecr = int.from_bytes(ts_buf[4:8], "big")
        if TCP_OPT_MSS in self.opts.keys():
            self.MSS = int.from_bytes(self.opts[TCP_OPT_MSS], "big")

    def set_ip(self, ip):
        self.src_ip = ip.src
        self.dst_ip = ip.dst


def ip_pkg(buf):
    eth = Ethernet(buf)
    if eth.type == ETH_TYPE_IP or eth.type == ETH_TYPE_IP6:
        return IP(eth.data)
    return None


def tcp_pkg(ip):
    if ip.protocol == IP_PROTO_TCP:
        tcp = TCP(ip.data)
        tcp.set_ip(ip)
        return tcp
    return None