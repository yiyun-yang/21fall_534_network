# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
@time: 2021/9/21 20:01
"""
import sys
import time

import dns.name
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.dnssec
import random
from dns.rrset import RRset


class DNSSec_Exception(Exception):
    def __init__(self, message="Salary is not in (5000, 15000) range"):
        self.message = message
        super().__init__(self.message)

# this list is copied from www.iana.org/domains/root/servers
root_server_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                    '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129',
                    '199.7.83.42', '202.12.27.33']

# keys are copied from https://data.iana.org/root-anchors/root-anchors.xml
root_algorithm = dns.dnssec.DSDigest.SHA256
root_anchors = []  # every item is a DS record
for anchor in ["19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
               "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]:
    root_anchors.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, anchor))


def sec_resolver(cur_domain, cur_type: dns.rdatatype, result_list, key_dict):
    random.shuffle(root_server_list)  # shuffle root_server list, so that it can be visited randomly

    # 0. query for root server's KSK and verify itself
    root_ip, root_dnskey_resp = issue_dnssec_request(root_server_list, dns.rdatatype.DNSKEY, ".",
                                                     lambda x: len(x.answer) > 0)
    verify_zone(root_dnskey_resp.answer, root_anchors, key_dict)
    verify_record(root_dnskey_resp.answer, key_dict)

    # 1. issue request to root server
    #   1.1 query root server for non-secured referrals, DS, and their related RRSIG.
    _, root_resp = issue_dnssec_request([root_ip], cur_type, cur_domain)
    #   1.2 start the dnssec verification
    tld_ip_list = to_ipv4_list(root_resp.additional)
    authenticate(root_resp, tld_ip_list, key_dict)

    # 2. issue request to TLD
    tld_ip, tld_resp = issue_dnssec_request(tld_ip_list, cur_type, cur_domain)

    # 3. issue request to Name Server after dnssec verification
    prev_resp = tld_resp
    while not check_ans(cur_type, prev_resp):
        if len(prev_resp.answer) != 0:  # answer is returned but contains only CNAME
            result_list.append(prev_resp.answer)  # add current answer to result_list
            if cur_type == dns.rdatatype.A:  # resolve CNAME, only when query_type is A, otherwise return answer.
                sec_resolver(get_cname(prev_resp.answer), cur_type, result_list, key_dict)
            return

        if len(prev_resp.additional) > 0:  # answer is empty, query by additional info
            ns_ipv4_list = to_ipv4_list(prev_resp.additional)
            authenticate(prev_resp, ns_ipv4_list, key_dict)     # dnssec verification
            _, prev_resp = issue_dnssec_request(ns_ipv4_list, cur_type, cur_domain)
        else:
            ns_result_list = []  # additional is empty, query by authoritative server
            authority_domain = get_authority_domain(prev_resp)
            if authority_domain is None:
                return
            sec_resolver(authority_domain, dns.rdatatype.A, ns_result_list, key_dict)
            ns_ipv4_list = to_ipv4_list(ns_result_list[-1])
            authenticate(prev_resp, ns_ipv4_list, key_dict)  # dnssec verification
            _, prev_resp = issue_dnssec_request(ns_ipv4_list, cur_type, cur_domain)
    result_list.append(prev_resp.answer)


def authenticate(prev_resp, next_ip_list, key_dict):
    #   0 check if DS record exist
    prev_ds_list = to_ds_list(prev_resp.authority)
    if len(prev_ds_list) == 0:
        raise DNSSec_Exception(f'“DNSSEC not supported')
    #   1 query for sub zone's DNS key
    _, dnskey_resp = issue_dnssec_request(next_ip_list, dns.rdatatype.DNSKEY, get_authority_name(prev_resp),
                                              lambda x: len(x.answer) > 0)
    #   2 compare sub zone's key's hashing with prev_resp's DS record
    verify_zone(dnskey_resp.answer, prev_ds_list, key_dict)
    #   3 verify sub zone's RRSIG with its own key
    verify_record(dnskey_resp.answer, key_dict)
    #   4 verify prev_resp's DS RRSIG with sub zone's public key
    verify_record(prev_resp.authority, key_dict)


def issue_dnssec_request(ipv4_list, query_type, query_domain, condition=lambda x: True):
    for ip in ipv4_list:
        try:
            # increase payload size so that response will not be truncated
            req = dns.message.make_query(query_domain, query_type, payload=4096, request_payload=4096, want_dnssec=True)
            res = dns.query.udp(req, ip, timeout=15)
            if condition(res):
                return ip, res
        except Exception as e:
            print(f'query ip {ip} domain {query_domain} type {dns.rdatatype.to_text(query_type)} failed: {e}')
    raise DNSSec_Exception(f'Request {query_domain} for all Servers failed')


def verify_zone(rr_set_list, previous_ds_list, key_dict):
    for rr_set in rr_set_list:
        if rr_set.rdtype == dns.rdatatype.DNSKEY:
            for item in rr_set.items:
                for prev_ds in previous_ds_list:        # transform DNSKEY to a DS
                    cur_ds = dns.dnssec.make_ds(rr_set.name, item, prev_ds.digest_type)
                    if cur_ds.to_text() == prev_ds.to_text():        # compare it with the previous DS
                        key_dict[rr_set.name] = rr_set  # name key pair is then put to the dict after verification
                        return
    raise DNSSec_Exception("Zone verification failed. ")


def verify_record(rr_set_list, key_dict):
    rrsigset = None
    for rr_set in rr_set_list:
        if rr_set.rdtype == dns.rdatatype.RRSIG:
            rrsigset = rr_set

    rrset = None
    for rr_set in rr_set_list:
        if rr_set.rdtype == rrsigset.covers:
            rrset = rr_set

    dns.dnssec.validate(rrset, rrsigset, key_dict)


def an_item_to_text(rr_set: RRset):
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


def get_authority_name(resp: dns.message.Message):
    for rr_set in resp.authority:
        return rr_set.name


def to_ipv4_list(rr_set_list):
    return [an_item_to_text(x) for x in rr_set_list if x.rdtype == dns.rdatatype.A]


def to_ds_list(rr_set_list):
    ds_list = []
    for rr_set in rr_set_list:
        if rr_set.rdtype == dns.rdatatype.DS:
            for item in rr_set.items:
                ds_list.append(item)
    return ds_list


def check_ans(query_type: dns.rdatatype, resp):
    for ans in resp.answer:
        if ans.rdtype == query_type:
            return True
    return False


def main():
    try:
        query_domain = sys.argv[1]
        rdtype = sys.argv[2]
        start_time = time.time()
        result_list = []
        sec_resolver(query_domain, dns.rdatatype.from_text(rdtype), result_list, {})
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
    except (dns.dnssec.ValidationFailure, dns.dnssec.UnsupportedAlgorithm, DNSSec_Exception):
        print(f'DNSSec verification failed')
    except:
        print(f'DNSSEC not supported')



if __name__ == "__main__":
    main()
