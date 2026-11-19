"""Classic PCAP reader/writer, bounded input; deliberately excludes PCAPNG."""
import math
import struct
from .capture import RawPacket

def write_pcap(path, packets):
    packets=list(packets)
    if not packets:raise ValueError('没有可保存的数据包')
    linktype=packets[0].linktype
    if any(p.linktype!=linktype for p in packets):raise ValueError('经典 PCAP 不支持在同一文件混用链路类型')
    with open(path,'wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,linktype))
        for p in packets:
            if not math.isfinite(p.timestamp) or not 0<=p.timestamp<2**32:raise ValueError('时间戳超出 PCAP 范围')
            sec=int(p.timestamp);micro=min(999999,int(round((p.timestamp-sec)*1e6)))
            f.write(struct.pack('<IIII',sec,micro,len(p.data),p.wire_length));f.write(p.data)

def read_pcap(path, max_packets=10000, max_bytes=32*1024*1024):
    records=[];total=0
    with open(path,'rb') as f:
        header=f.read(24)
        if len(header)!=24:raise ValueError('PCAP 文件头不完整')
        modes={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
        if header[:4] not in modes:raise ValueError('仅支持经典 PCAP；请将 PCAPNG 转换为 PCAP')
        endian,scale=modes[header[:4]];major,minor,zone,sig,snaplen,linktype=struct.unpack(endian+'HHIIII',header[4:])
        if (major,minor)!=(2,4) or not 1<=snaplen<=65535:raise ValueError('不支持的 PCAP 版本或快照长度')
        while True:
            h=f.read(16)
            if not h:break
            if len(h)!=16:raise ValueError('PCAP 记录头截断')
            sec,frac,caplen,wire=struct.unpack(endian+'IIII',h)
            if caplen>snaplen or caplen>wire or frac>=scale:raise ValueError('PCAP 记录长度或时间戳无效')
            total+=caplen
            if total>max_bytes or len(records)>=max_packets:raise ValueError('文件超过内存保护上限：10000 包或 32 MiB')
            data=f.read(caplen)
            if len(data)!=caplen:raise ValueError('PCAP 数据被截断')
            records.append(RawPacket(sec+frac/scale,data,wire,linktype))
    return records
