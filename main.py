from sys import byteorder
import dns.resolver

import dns.message
import dns.name
import dns.rdatatype
import dns.query

import socket
import secrets
import binascii

def dnsquery_hl(query: str):
    # dns.resolver.Answer
    answer = dns.resolver.resolve(query)
    # dns.resolver.Answer / dns.rrset.RRset / dns.rdtypes.IN.A.A
    for rd in answer.rrset.processing_order():
        print(rd.address)

def dnsquery_ml(query: str):
    # dns.name.Name
    qname = dns.name.from_text(query)
    # dns.message.QueryMessage
    qmsg = dns.message.make_query(qname, dns.rdatatype.A)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        response = dns.query.udp(qmsg, '8.8.8.8', sock=sock)
    # dns.message.QueryMessage / dns.rrset.RRset / dns.rdtypes.IN.A.A
    for rrset in response.answer:
        print(rrset.name, end=' ')
        for rd in rrset.processing_order():
            print(rd, end=' ')
        print()

if __name__ == "__main__":
    dnsquery_ml("www.nyu.com")
