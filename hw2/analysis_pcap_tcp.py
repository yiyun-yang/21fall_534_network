# -*- coding:utf-8 -*-
import math

import dpkt
import pandas as pd
import math

from Packet import *

# flow field index
# key index
SRC_PORT = 0
DST_PORT = 1
IP_DST = 2
# value index
FLOW_COUNT = 0
WIN_SCALE = 1
START_TIME = 2
END_TIME = 3
MSS = 4
LEN_PKT_SENT = 5
RTT_FIRST_ACK = 6
NUM_PKT_SENT = 7
TOTAL_BYTES = 8
RTT_INFO = 9
SENT_TIME_LIST = 10



def count_tcp_flows(pcap_path, sender):
    flows = {}  # key-value definition refers to the constant variable above
    first2_tran: dict[list] = {}  # {key: [(seq, ack, win_bytes, len)]}
    seq_ack_counter = {}   # {dst_port: {seq/ack, (sent_cnt, rev_cnt)}}

    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            ip = ip_pkg(buf)
            if ip is None: continue  # skip non-ip packets

            tcp = tcp_pkg(ip)
            if tcp is None: continue  # skip non-TCP packets
            payload_len = len(tcp.data)

            # send
            if ip.src == sender:
                if payload_len == 0 and not tcp.flags & TH_SYN:     # ignore payload 0 and not SYN packets
                    continue

                key = (tcp.src_port, tcp.dst_port, ip.dst)  # distinct key for each TCP flow
                if tcp.src_port not in seq_ack_counter.keys(): seq_ack_counter[tcp.src_port] = {}
                if tcp.seq not in seq_ack_counter[tcp.src_port]:
                    seq_ack_counter[tcp.src_port][tcp.seq] = [1, 0]
                else:
                    seq_ack_counter[tcp.src_port][tcp.seq][0] += 1

                if tcp.flags & TH_SYN:  # when connection is setup
                    if key not in flows.keys(): # a new TCP flow
                        flows[key] = [0,0,0,0,0,[0],None,[1],0,{},{}]
                    flows[key][FLOW_COUNT] += 1  # increment TCP flow cnt by 1
                    flows[key][WIN_SCALE] = tcp.win_scale
                    flows[key][START_TIME] = ts
                    flows[key][MSS] = tcp.MSS
                    expected_ack = tcp.seq + 1
                else:
                    expected_ack = tcp.seq + payload_len

                if expected_ack in flows[key][SENT_TIME_LIST]:
                    flows[key][SENT_TIME_LIST][expected_ack].append(ts)
                else:
                    flows[key][SENT_TIME_LIST][expected_ack] = [ts]

                flows[key][RTT_INFO][expected_ack] = [ts, ts] # send_time, rev_time

                if tcp.flags & TH_ACK and payload_len > 0:  # ACK and payload size > 0
                    if key not in first2_tran: first2_tran[key] = []    # process the first2_tran
                    if len(first2_tran[key]) < 4:
                        sent_cnt = 0
                        for tran in first2_tran[key]:
                            if tran[4]=='SENT': sent_cnt += 1
                        if sent_cnt < 2: first2_tran[key].append((tcp.seq, tcp.ack, tcp.win_size, len(tcp.data), "SENT"))
            # receive
            elif ip.dst == sender:
                key = (tcp.dst_port, tcp.src_port, ip.src)  # distinct key for each TCP flow
                if tcp.ack in seq_ack_counter[tcp.dst_port]:
                    seq_ack_counter[tcp.dst_port][tcp.ack][1] += 1

                if tcp.flags & TH_FIN:  # connection closed ACK received
                    flows[key][END_TIME] = ts

                if key in first2_tran.keys() and len(first2_tran[key]) < 4:
                    is_first2 = False
                    for tran in first2_tran[key]:
                        if tran[4] == 'SENT' and tcp.seq == tran[1] and tcp.ack == tran[0]+tran[3]:
                            is_first2 = True
                            break
                    if is_first2: first2_tran[key].append((tcp.seq, tcp.ack, tcp.win_size, len(tcp.data), "RECEIVE"))

                if tcp.ack in flows[key][RTT_INFO]:
                    send_time, rev_time = flows[key][RTT_INFO][tcp.ack]
                    if send_time == rev_time:
                        flows[key][RTT_INFO][tcp.ack][1] = ts

            flows[key][TOTAL_BYTES] += len(buf)

    print(f'======== Part A. Q1 ========')
    total = 0
    for k in flows:
        print(f'src_port: {k[SRC_PORT]}, dst_port: {k[DST_PORT]}, ip_dst: {k[IP_DST]}, count: {flows[k][FLOW_COUNT]}')
        total += flows[k][FLOW_COUNT]
    print(f'TCP flows sent from {sender}: {total}')

    print(f'\n======== Part A. Q2(a) ========')
    for k in first2_tran:
        print(f'src_port: {k[SRC_PORT]}, dst_port: {k[DST_PORT]}, ip_dst: {k[IP_DST]}, win_scale: {flows[k][WIN_SCALE]}')
        win_scale = flows[k][WIN_SCALE]
        for seq, ack, win_size, length, title in first2_tran[k]:
            win_bytes = tran[2]<< win_scale
            print(f'{title} seq: {seq}, ack: {ack}, win_size: {win_size}, win_bytes: {win_bytes}, len: {length}')
        print()

    print(f'======== Part A. Q2(b) ========')
    for k in flows:
        interval = float(flows[k][END_TIME] - flows[k][START_TIME])
        print(f'src_port: {k[SRC_PORT]}, dst_port: {k[DST_PORT]}, interval: {"{:.2f}".format(interval)} seconds')
        throughput = flows[k][TOTAL_BYTES] * 8 / (interval * 1000000)
        print(f'total: {flows[k][TOTAL_BYTES] * 8} bytes, throughput: {"{:.3f}".format(throughput)} Mbps')
        print()

    print(f'======== Part A. Q2(b) ========')
    loss_rates = {}
    for k in flows:
        port = k[SRC_PORT]
        transmitted = 0
        loss = 0
        for sent_cnt, rev_cnt in seq_ack_counter[port].values():
            transmitted += 1
            if sent_cnt > 1:
                loss += 1
            elif rev_cnt > 1:
                loss += 1
        cur_loss_rate = loss / transmitted
        print(f'loss: {loss}, transmitted: {transmitted}, port: {port}, loss rate: {cur_loss_rate}')
        loss_rates[port] = cur_loss_rate

    print(f'\n======== Part A. Q2(c) ========')
    rtt_by_port = {}
    for k in flows:
        rtt_cnt = 0
        rtt_sum = 0
        for [send_time, rev_time] in flows[k][RTT_INFO].values():
            if rev_time > send_time:
                rtt_cnt += 1
                rtt_sum += rev_time - send_time
        mss = flows[k][MSS]
        avg_rtt = rtt_sum/rtt_cnt
        port = k[SRC_PORT]
        cur_loss_rate = loss_rates[port]
        theoretical_throughput = float('inf')
        if cur_loss_rate > 0:
            theoretical_throughput = (math.sqrt(3 / 2) * mss * 8) / (avg_rtt * math.sqrt(cur_loss_rate)) / 1000000
        print(f'port: {port}, avg_rtt: {"{:.6f}".format(avg_rtt)} s, MSS: {mss} bytes, '
              f'theoretical throughput: {"{:.5f}".format(theoretical_throughput)} Mbps')
        rtt_by_port[port] = 0.08

    print(f'\n======== Part B (1) ========')
    for k in flows:
        port = k[SRC_PORT]
        rtt = rtt_by_port[port]
        pkt_list = list(flows[k][RTT_INFO].values())
        pkt_list.sort(key=lambda x:x[0])    # sort by start time
        pkt_list = pkt_list[1:]     # exclude handshake packets
        st_time = flows[k][START_TIME]

        pkt_df = pd.DataFrame(pkt_list, columns=["send_time", "rev_time"])
        pkt_df["rtt_no"] = pkt_df.apply(lambda x: math.ceil((x['send_time']-st_time) / rtt), axis='columns')
        pkt_df = pkt_df[pkt_df["rtt_no"] <= 10]
        counts_in_rtt_dict = pkt_df.groupby('rtt_no').size().to_dict()
        for sent_time_list in flows[k][SENT_TIME_LIST].values():
            for t in sent_time_list[1:]:
                rtt_no = math.ceil((t-st_time) / rtt)
                if rtt_no <= 10:
                    counts_in_rtt_dict[rtt_no] += 1
        counts_in_rtt = list(counts_in_rtt_dict.values())

        cwnd_increase_rate = []
        for i, x in enumerate(counts_in_rtt):
            if i == 0:
                cwnd_increase_rate.append(1)
            else:
                cwnd_increase_rate.append(round(x / counts_in_rtt[i-1], 2))

        cur_mss = flows[k][MSS]
        print(f'src port: {port}, MSS: {cur_mss} bytes')
        print(f'packet count of each RTT: {counts_in_rtt}')
        print(f'congestion window size in each RTT: {[x * cur_mss for x in counts_in_rtt]}')
        print(f'increase rate: {cwnd_increase_rate}')
        print()

    print(f'\n======== Part B (2) ========')
    for k in flows:
        port = k[SRC_PORT]
        print(f'src port: {port}')
        retransmission = 0
        dup_acks = 0
        for sent_cnt, rev_cnt in seq_ack_counter[port].values():
            if sent_cnt > 1:
                retransmission += 1
            elif rev_cnt > 1:
                dup_acks += 1
        print(f'retransmitted by dupACKs: {dup_acks}')
        print(f'retransmitted by timeout: {retransmission}')
        print()


if __name__ == '__main__':
    sender = "130.245.145.12"
    receiver = "128.208.2.198"

    pcap_path = "./assignment2.pcap"
    if len(sys.argv) > 1: pcap_path = sys.argv[1]

    count_tcp_flows(pcap_path, sender)
