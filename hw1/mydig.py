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


# this list is copied from www.iana.org/domains/root/servers
root_server_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                    '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129',
                    '199.7.83.42', '202.12.27.33']


def dns_resolver(cur_domain, cur_type: dns.rdatatype, result_list):
    random.shuffle(root_server_list)  # shuffle root_server list, so that it can be visited randomly

    # 1. issue request to root server
    root_resp = issue_request(root_server_list, cur_type, cur_domain)
    # 2. issue request to TLD
    tld_ip_list = to_ipv4_list(root_resp.additional)
    tld_resp = issue_request(tld_ip_list, cur_type, cur_domain)

    # 3. issue request to Name Server
    prev_resp = tld_resp
    while not check_ans(cur_type, prev_resp):
        if len(prev_resp.answer) != 0:      # answer is returned but contains only CNAME
            result_list.append(prev_resp.answer)    # add current answer to result_list
            dns_resolver(get_cname(prev_resp.answer), cur_type, result_list)
            return

        if len(prev_resp.additional) > 0:   # answer is empty, query by additional info
            ns_ipv4_list = to_ipv4_list(prev_resp.additional)
            prev_resp = issue_request(ns_ipv4_list, cur_type, cur_domain)
        else:
            ns_result_list = []              # additional is empty, query by authoritative server
            authority_domain = get_authority_domain(prev_resp)
            if authority_domain is None:
                return
            dns_resolver(authority_domain, dns.rdatatype.A, ns_result_list)
            ns_ipv4_list = to_ipv4_list(ns_result_list[-1])
            prev_resp = issue_request(ns_ipv4_list, cur_type, cur_domain)

    result_list.append(prev_resp.answer)


def issue_request(ipv4_list, query_type, query_domain):
    for ip in ipv4_list:
        try:
            req = dns.message.make_query(query_domain, query_type)
            return dns.query.udp(req, ip, timeout=1)
        except Exception as e:
            print(f'query ip {ip} domain {query_domain} type {dns.rdatatype.to_text(query_type)} failed: {e}')
    raise Exception(f'Request {query_domain} for all Servers failed')


def an_item_to_text(rr_set: dns.rrset.RRset):
    for item in rr_set.items:
        return item.to_text()


def get_cname(rr_set_list):
    for rr_set in rr_set_list:
        if rr_set.rdtype == dns.rdatatype.CNAME:
            return an_item_to_text(rr_set)


def get_authority_domain(resp: dns.message.Message):
    for rr_set in resp.authority:
        if rr_set.rdtype == dns.rdatatype.NS or rr_set.rdtype == dns.rdatatype.CNAME:
            return an_item_to_text(rr_set)


def to_ipv4_list(rr_set_list):
    return [an_item_to_text(x) for x in rr_set_list if x.rdtype == dns.rdatatype.A]


def check_ans(query_type: dns.rdatatype, resp):
    for ans in resp.answer:
        if ans.rdtype == query_type:
            return True
    return False


def main():
    query_domain = sys.argv[1]
    rdtype = sys.argv[2]
    start_time = time.time()
    result_list = []
    dns_resolver(query_domain, dns.rdatatype.from_text(rdtype), result_list)
    end_time = time.time()

    output = [f'QUESTION SECTION:\n{query_domain}			IN	{rdtype}\n', "ANSWER SECTION: "]
    for result in result_list:
        for rr_set in result:
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