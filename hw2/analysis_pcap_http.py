# -*- coding:utf-8 -*-

import dpkt

from Packet import *

# key index
REQ_PORT = 0
RES_PORT = 1

port_info = {}

def req_res(pcap_path, port):
    global port_info
    responses = {}  # key value definition refers to the constant variable above
    requests = {}
    pkt_list = []
    bytes_total = 0
    packet_total = 0
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            packet_total += 1
            ip = ip_pkg(buf)
            if ip is None: continue  # skip non-ip packets
            tcp = tcp_pkg(ip)
            tcp.time = ts
            bytes_total += len(buf)
            if tcp is None: continue  # skip non-TCP packets
            pkt_list.append(tcp)

    # process response
    ed_time = None
    for tcp in pkt_list:
        payload_len = len(tcp.data)
        if tcp.src_port == port and payload_len > 0:
            key = (tcp.dst_port, tcp.src_port)  # distinct key for each TCP flow
            if key not in responses:
                responses[key] = {}
            if tcp.seq not in responses[key]:
                responses[key][tcp.seq] = []
            responses[key][tcp.seq].append(f'({tcp.src_port}, {tcp.dst_port}, {tcp.seq}, {tcp.ack})')
            ed_time = tcp.time

    # process request according to ack in responses with payload > 0
    st_time = None
    for tcp in pkt_list:
        payload_len = len(tcp.data)
        if tcp.dst_port == port and payload_len > 0:
            key = (tcp.src_port, tcp.dst_port)  # distinct key for each TCP flow
            if key not in requests:
                requests[key] = {}
            requests[key][tcp.ack] = f'({tcp.src_port}, {tcp.dst_port}, {tcp.seq}, {tcp.ack})'
            if st_time is None:
                st_time = tcp.time

    print(f'=========== port: {port} ===========')
    http_flow = 0
    for k, ack_dict in requests.items():
        if port != 1080:
            print(f'For TCP connection on {k}')
        for req_seq, x in ack_dict.items():
            if req_seq not in responses[k]:
                continue
            http_flow += 1
            for y in set(responses[k][req_seq]):
                print(f'Request: {x}, Response: {y}')
            # print()

    print(f'data flows: {http_flow}')
    print(f'tcp connections: {len(responses)}')
    port_info[port] = f'interval: {"{:.3f}".format(ed_time-st_time)} s\n' \
                      f'packet_total: {packet_total}\n' \
                      f'payload_total: {bytes_total} bytes'


if __name__ == '__main__':
    req_res("http_1080.pcap", 1080)
    req_res("tcp_1081.pcap", 1081)
    req_res("tcp_1082.pcap", 1082)
    print(f'=========== summary ===========')
    for p, text in port_info.items():
        print(f'port: {p}')
        print(text)
        print()
