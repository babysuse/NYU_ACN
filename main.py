import dns.resolver

import dns.message
import dns.name
import dns.rrset
import dns.rdatatype
import dns.query

import socket
import secrets
import binascii

def parse_dns_qmsg(qmsg: dns.message.QueryMessage):
    if not qmsg.answer:
        print('Result not found')
        return
    for rrset in qmsg.answer:
        parse_dns_rrset(rrset)

def parse_dns_rrset(rrset: dns.rrset.RRset):
    # dns.rrset.RRset / dns.rdtypes.IN.A.A
    for rd in rrset.processing_order():
        print(rd)

def dnsquery_hl(query: str):
    # dns.resolver.Answer
    try:
        answer = dns.resolver.resolve(query)
    except dns.resolver.NXDOMAIN:
        print('Result not found')
    else:
        parse_dns_rrset(answer.rrset)

def dnsquery_ml(query: str):
    # dns.name.Name
    qname = dns.name.from_text(query)
    # dns.message.QueryMessage
    qmsg = dns.message.make_query(qname, dns.rdatatype.A)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # dns.message.QueryMessage
        resp_qmsg = dns.query.udp(qmsg, '8.8.8.8', sock=sock)
    parse_dns_qmsg(resp_qmsg)

def dnsquery_ll(query: str):
    """
    HEADER
    0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ QR: 0 (Query)
    | ID                                            | Opcode: 0 (stander query)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ RD: 1 (Recursive Desired) => 01
    |QR| Opcode    |AA|TC|RD|RA| Z      | RCODE     | 
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ RA (Recursive Available): 0
    | QDCOUNT                                       | Z (Zero): 0
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ RCODE (Response Code): 0 => 00
    | ANCOUNT                                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ QDCOUNT => 00 01
    | NSCOUNT                                       | AN-/NS-/ARCOUNT => 00 00
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | ARCOUNT                                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    # making request
    flags  = '01 00 '
    flags += '00 01 '
    flags += '00 00 ' * 3
    query_header = secrets.token_bytes(2) + binascii.unhexlify(flags.replace(" ", ""))

    query = query.strip('.')
    payload = b''
    for q in query.split('.'):
        payload += len(q).to_bytes(length=1, byteorder='big')
        payload += q.encode()
    payload += int.to_bytes(0, length=1, byteorder='big')
    
    # QTYPE (1 for A record), QCLASS (1 for internet)
    payload += int.to_bytes(1, length=2, byteorder='big')
    payload += int.to_bytes(1, length=2, byteorder='big')

    query_msg = query_header + payload
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        server_addr = ('8.8.8.8', 53)
        sock.sendto(query_msg, server_addr)
        # dns.message.QueryMessage
        # resp_qmsg, _ = dns.query.receive_udp(sock, destination=server_addr)
        resp_msg, _ = sock.recvfrom(65535)
    qmsg = dns.message.from_wire(resp_msg)
    parse_dns_qmsg(qmsg)

if __name__ == "__main__":
    query = input("Input domain: ")
    while not query:
        query = input("Input a non-empty domain: ")
    dnsquery_ll(query)
