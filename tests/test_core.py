import os
import random
import struct
import tempfile
import unittest
import ipaddress
from pathlib import Path
from sniffer.capture import RawPacket
from sniffer.protocols import decode,dns_name
from sniffer.filters import compile_filter
from sniffer.pcapio import read_pcap,write_pcap
from sniffer.streams import reconstruct

def tcp(payload=b'',seq=100,flags=0x18,sport=1234,dport=8088):
    return struct.pack('!HHIIBBHHH',sport,dport,seq,0,0x50,flags,65535,0,0)+payload
def udp(payload=b'',sport=1234,dport=53):return struct.pack('!HHHH',sport,dport,len(payload)+8,0)+payload
def ipv4(payload,proto=6,frag=0,reverse=False):
    src,dst=(b'\x0a\x00\x00\x01',b'\x0a\x00\x00\x02')
    if reverse:src,dst=dst,src
    return struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),1,frag,64,proto,0,src,dst)+payload
def ipv6(payload,proto=17):
    return struct.pack('!IHBB16s16s',6<<28,len(payload),proto,64,ipaddress.ip_address('::1').packed,ipaddress.ip_address('2001:db8::2').packed)+payload
def frame(payload,ether=0x800,link=1):
    prefix=b'\x00'*12+struct.pack('!H',ether) if link==1 else struct.pack('<I',2 if ether==0x800 else 23) if link==0 else b''
    data=prefix+payload;return RawPacket(1795150000.25,data,len(data),link)
def packet(payload=b'',seq=100,flags=0x18):return decode(frame(ipv4(tcp(payload,seq,flags))))

class ProtocolTests(unittest.TestCase):
    def test_http_on_nonstandard_port(self):
        p=packet(b'GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n')
        self.assertEqual(p.protocol,'HTTP');self.assertEqual(p.sport,1234);self.assertEqual(p.source,'10.0.0.1');self.assertIn('TCP',p.layers)
    def test_port_not_identity(self):
        p=decode(frame(ipv4(tcp(b'not http',dport=80))))
        self.assertEqual(p.protocol,'TCP')
    def test_tls_header(self):self.assertEqual(packet(b'\x16\x03\x03\x00\x04abcd').protocol,'TLS')
    def test_dns_question(self):
        dns=struct.pack('!6H',0x1234,0x100,1,0,0,0)+b'\x07example\x03com\x00\x00\x01\x00\x01'
        p=decode(frame(ipv4(udp(dns),17)));self.assertEqual(p.protocol,'DNS');self.assertIn('example.com',p.info)
    def test_dns_compression_cycle(self):
        with self.assertRaises(ValueError):dns_name(b'\xc0\x00',0)
    def test_ipv6_udp(self):
        p=decode(frame(ipv6(udp(b'hello',dport=5555)),0x86dd));self.assertEqual(p.protocol,'UDP');self.assertEqual(p.source,'::1')
    def test_ipv6_extension(self):
        p=decode(frame(ipv6(bytes([17,0])+b'\0'*6+udp(b'x'),0),0x86dd));self.assertIn('UDP',p.layers)
    def test_ipv6_fragment_not_misparsed(self):
        p=decode(frame(ipv6(struct.pack('!BBHI',6,0,9,1)+b'x'*20,44),0x86dd));self.assertNotIn('TCP',p.layers);self.assertIn('分片',p.warning)
    def test_ipv4_fragment_not_misparsed(self):
        p=decode(frame(ipv4(tcp(b'x'),frag=0x2000)));self.assertNotIn('TCP',p.layers)
    def test_icmp(self):self.assertEqual(decode(frame(ipv4(b'\x08\0\0\0abcd',1))).protocol,'ICMP')
    def test_icmpv6(self):self.assertEqual(decode(frame(ipv6(b'\x80\0\0\0abcd',58),0x86dd)).protocol,'ICMPv6')
    def test_arp(self):
        data=struct.pack('!HHBBH',1,0x800,6,4,1)+b'\0'*6+b'\x0a\0\0\1'+b'\0'*6+b'\x0a\0\0\2'
        p=decode(frame(data,0x806));self.assertEqual(p.protocol,'ARP');self.assertEqual(p.destination,'10.0.0.2')
    def test_vlan(self):
        p=decode(frame(struct.pack('!HH',42,0x800)+ipv4(tcp()),0x8100));self.assertIn('VLAN',p.layers);self.assertIn('TCP',p.layers)
    def test_loopback(self):self.assertIn('TCP',decode(frame(ipv4(tcp()),link=0)).layers)
    def test_tcp_invalid_header(self):
        b=bytearray(tcp());b[12]=0x10;p=decode(frame(ipv4(b)));self.assertIn('头长',p.warning)
    def test_udp_short_length(self):
        p=decode(frame(ipv4(struct.pack('!HHHH',1,2,2,0),17)));self.assertIn('UDP 长度',p.warning)
    def test_every_truncation(self):
        original=frame(ipv4(tcp(b'GET / HTTP/1.1\r\n\r\n')))
        for i in range(len(original.data)):decode(RawPacket(1,original.data[:i],len(original.data),1))
    def test_random_malformed_frames(self):
        rng=random.Random(1)
        for i in range(2000):
            data=rng.randbytes(rng.randrange(0,160));decode(RawPacket(1,data,len(data),rng.choice([0,1,101,108,113,276,999])))

class FilterTests(unittest.TestCase):
    def test_protocol_layer_membership(self):self.assertTrue(compile_filter('tcp and http')(packet(b'GET / HTTP/1.1\r\n')))
    def test_precedence(self):self.assertTrue(compile_filter('udp or tcp and not port 80')(packet()))
    def test_parentheses(self):self.assertFalse(compile_filter('(udp or tcp) and port 80')(packet()))
    def test_addresses(self):self.assertTrue(compile_filter('src 10.0.0.1 and dst 10.0.0.2 and sport 1234')(packet()))
    def test_invalid_rejected(self):
        for value in ['tcp udp','port -1','port 99999','host bad','tcp and','(tcp','__import__(os)','not '*40+'tcp']:
            with self.subTest(value=value),self.assertRaises(ValueError):compile_filter(value)

class StreamTests(unittest.TestCase):
    def test_out_of_order_and_retransmission(self):
        r,_=reconstruct([packet(b'world',105),packet(b'hello',100),packet(b'hello',100)])
        self.assertEqual(r[0]['chunks'],[b'helloworld']);self.assertEqual(r[0]['duplicate_bytes'],5)
    def test_gap_preserved(self):
        r,_=reconstruct([packet(b'a',100),packet(b'b',103)]);self.assertEqual(r[0]['missing_bytes'],2);self.assertEqual(r[0]['chunks'][2],b'b')
    def test_conflicting_overlap(self):
        r,_=reconstruct([packet(b'abc'),packet(b'axc')]);self.assertEqual(r[0]['conflicting_bytes'],1);self.assertEqual(r[0]['chunks'],[b'abc'])
    def test_sequence_wrap(self):
        r,_=reconstruct([packet(b'ab',0xfffffffe),packet(b'cd',0)]);self.assertEqual(r[0]['chunks'],[b'abcd'])
    def test_syn_sequence_consumption(self):
        r,_=reconstruct([packet(b'ab',100,2),packet(b'cd',103)]);self.assertEqual(r[0]['chunks'],[b'abcd'])
    def test_memory_cap(self):
        r,_=reconstruct([packet(b'abcdef')],limit=3);self.assertEqual(r[0]['unique_bytes'],3);self.assertEqual(r[0]['omitted_bytes'],3)
    def test_bidirectional_key(self):
        a=packet();b=decode(frame(ipv4(tcp(sport=8088,dport=1234),reverse=True)));self.assertEqual(a.flow_key,b.flow_key)

class PcapTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'a.pcap';p=frame(ipv4(tcp(b'hello')));write_pcap(path,[p]);self.assertEqual(read_pcap(path),[p])
    def test_big_endian_nanoseconds(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'a.pcap';path.write_bytes(struct.pack('>IHHIIII',0xa1b23c4d,2,4,0,0,65535,101)+struct.pack('>IIII',1,500000000,1,1)+b'x');self.assertEqual(read_pcap(path)[0].timestamp,1.5)
    def test_truncated_record(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'a.pcap';write_pcap(path,[frame(ipv4(tcp()))]);path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):read_pcap(path)
    def test_file_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'a.pcap';write_pcap(path,[frame(ipv4(tcp()))]*2)
            with self.assertRaises(ValueError):read_pcap(path,max_packets=1)
    def test_mixed_links_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):write_pcap(Path(folder)/'a.pcap',[frame(ipv4(tcp())),frame(ipv4(tcp()),link=0)])

if __name__=='__main__':unittest.main()
