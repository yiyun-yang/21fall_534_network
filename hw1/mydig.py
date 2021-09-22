# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
@time: 2021/9/21 13:21
"""
import sys
import time

import dns.name
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import random


def dns_resolver(query_domain, query_type: dns.rdatatype):
    # this list is copied from www.iana.org/domains/root/servers
    root_server_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                        '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129',
                        '199.7.83.42', '202.12.27.33']
    random.shuffle(root_server_list)  # shuffle root_server list, so that it can be visited randomly

    # 1. query root server
    root_resp = query_from_root(root_server_list, query_type, query_domain)
    if root_resp is None:
        print(f'Request for all root servers failed')
        return

    # 2. query TLD
    tld_resp = query_from_additional(root_resp, query_type, query_domain)
    if tld_resp is None:
        print(f'Request for all TLD servers failed')
        return

    # If queried type is NS, then we can stop here
    if query_type == dns.rdatatype.NS:
        return tld_resp.authority

    # 3. query Name Server
    prev_resp = tld_resp
    while True:
        ns_resp = query_from_additional(prev_resp, query_type, query_domain)
        prev_additional = prev_resp.additional
        if ns_resp is None:
            prev_cname = get_cname(prev_additional)
            if prev_cname is not None:      # Only CNAME records returned in PREVIOUS answer, query by CNAME
                return dns_resolver(prev_cname, query_type)
            print(f'Request for all Name Servers failed')
            return
        # check if result is in the answer
        for ans in ns_resp.answer:
            if ans.rdtype == query_type:
                return ns_resp.answer
        cur_cname = get_cname(ns_resp.answer)
        if cur_cname is not None:           # Only CNAME records returned in CURRENT answer, query by CNAME
            return dns_resolver(cur_cname, query_type)
        prev_resp = ns_resp                 # No matching records in current answer, continue query by 'additional'


def query_from_root(root_server_list, query_type, query_domain):
    for ip in root_server_list:
        try:
            resp = single_query(query_domain, query_type, ip)
            if resp.rcode() == dns.rcode.NOERROR:
                return resp
        except Exception as e:
            print(f'query server {ip} type {dns.rdatatype.to_text(query_type)} failed: {e}')
    print(f'Request for all Root Servers failed')


def query_from_additional(prev_resp, query_type, query_domain):
    for rr_set in ipv4_records(prev_resp.additional):
        ip = get_ip(rr_set)
        try:
            resp = single_query(query_domain, query_type, ip)
            if resp.rcode() == dns.rcode.NOERROR:
                return resp
        except Exception as e:
            print(f'query server {ip} type {dns.rdatatype.to_text(query_type)} failed: {e}')
    print(f'Request for all Servers failed')


def single_query(query_domain, query_type: dns.rdatatype, dst_ip, timeout=10):
    req = dns.message.make_query(query_domain, query_type)
    return dns.query.udp(req, dst_ip, timeout)


def get_ip(rr_set: dns.rrset.RRset):
    for item in rr_set.items:
        return item.to_text()


def get_rdtype(rr_set_list: dns.rrset.RRset):
    for rr_set in rr_set_list:
        return rr_set.rdtype


def get_cname(rr_set_list: dns.rrset.RRset):
    for rr_set in rr_set_list:
        if rr_set.rdtype == dns.rdatatype.CNAME:
            return get_ip(rr_set)


def ipv4_records(rr_set_list):
    return [x for x in rr_set_list if x.rdtype == dns.rdatatype.A]


def main():
    query_domain = sys.argv[1]
    rdtype = sys.argv[2]
    start_time = time.time()
    rr_set_list = dns_resolver(query_domain, dns.rdatatype.from_text(rdtype))
    end_time = time.time()

    output = []
    output.append(f'QUESTION SECTION:\n{query_domain}			IN	{rdtype}\n')
    output.append("ANSWER SECTION: ")

    for rr_set in rr_set_list:
        cur_name = rr_set.name
        cur_class = dns.rdataclass.to_text(rr_set.rdclass)
        cur_type = dns.rdatatype.to_text(rr_set.rdtype)
        for ans in rr_set.items.keys():
            output.append(
                f"{cur_name} {cur_class} {cur_type} {ans.to_text()}")

    output.append(f'\nQuery time: {int((end_time - start_time) * 1000)} msec')
    output.append(f'WHEN: {time.asctime(time.localtime(end_time))}\n')

    rcvd = 0
    for o in output:
        rcvd += len(o)
        print(o)
    print(f'MSG SIZE rcvd: {rcvd}')


if __name__ == "__main__":
    main()