"""Length-checked packet decoding; ports alone never establish HTTP/TLS identity."""
import ipaddress
import struct
from dataclasses import dataclass, field
from .capture import RawPacket

@dataclass
class Packet:
    raw: RawPacket
    source: str = ''
    destination: str = ''
    sport: int | None = None
    dport: int | None = None
    protocol: str = '未知'
    layers: set = field(default_factory=set)
    details: list = field(default_factory=list)
    info: str = ''
    payload: bytes = b''
    sequence: int = 0
    flags: int = 0
    ip_version: int = 0
    warning: str = ''

    @property
    def flow_key(self):
        if 'TCP' not in self.layers or self.sport is None: return None
        return (self.ip_version, *sorted(((self.source,self.sport),(self.destination,self.dport))))

def dns_name(data, offset):
    labels=[]; visited=set(); end=None
    for _ in range(128):
        if offset >= len(data) or offset in visited: raise ValueError('DNS 名称越界或压缩指针循环')
        visited.add(offset); size=data[offset]; offset+=1
        if size == 0: return '.'.join(labels), end or offset
        if size & 0xc0 == 0xc0:
            if offset >= len(data): raise ValueError('DNS 指针截断')
            if end is None: end=offset+1
            offset=((size & 63)<<8)|data[offset]; continue
        if size & 0xc0 or offset+size>len(data): raise ValueError('DNS 标签无效')
        labels.append(data[offset:offset+size].decode('ascii',errors='replace')); offset+=size
    raise ValueError('DNS 名称过长')

def decode(raw):
    p=Packet(raw); b=raw.data
    def need(offset,count, end=None):
        if offset < 0 or offset+count > (len(b) if end is None else end): raise ValueError('报文截断或头部长度无效')
    def add(layer, **values):
        p.layers.add(layer); p.protocol=layer; p.details.append((layer,values))
    try:
        offset=0; ether=0
        if raw.linktype==1:
            need(0,14); ether=struct.unpack_from('!H',b,12)[0]; offset=14
            mac=lambda v: ':'.join(f'{x:02x}' for x in v)
            add('Ethernet',目的MAC=mac(b[:6]),源MAC=mac(b[6:12]),类型=f'0x{ether:04x}')
            for _ in range(4):
                if ether not in (0x8100,0x88a8): break
                need(offset,4); tci,ether=struct.unpack_from('!HH',b,offset); offset+=4
                add('VLAN',编号=tci&4095,优先级=tci>>13)
            else: raise ValueError('VLAN 嵌套超过限制')
        elif raw.linktype in (0,108):
            need(0,4); family=int.from_bytes(b[:4], 'little' if raw.linktype==0 else 'big'); offset=4
            ether=0x800 if family==2 else 0x86dd if family in (10,23,24,28,30) else 0
            add('Loopback',地址族=family)
        elif raw.linktype in (12,101):
            need(0,1); ether={4:0x800,6:0x86dd}.get(b[0]>>4,0)
        elif raw.linktype in (113,276):
            offset=16 if raw.linktype==113 else 20; need(0,offset)
            ether=struct.unpack_from('!H',b,14 if raw.linktype==113 else 0)[0]
            add('Linux cooked',版本=1 if raw.linktype==113 else 2)
        else: raise ValueError(f'不支持链路类型 {raw.linktype}')
        end=len(b); fragmented=False
        if ether==0x806:
            need(offset,8); ht,pt,hl,pl,op=struct.unpack_from('!HHBBH',b,offset)
            need(offset+8,2*(hl+pl)); o=offset+8
            if pt==0x800 and pl==4:
                p.source=str(ipaddress.ip_address(b[o+hl:o+hl+pl]));p.destination=str(ipaddress.ip_address(b[o+2*hl+pl:o+2*(hl+pl)]))
            add('ARP',操作=op,硬件类型=ht,协议类型=hex(pt));p.info=f'{"请求" if op==1 else "响应"} {p.source} → {p.destination}';return p
        if ether==0x800:
            need(offset,20); version=b[offset]>>4; ihl=(b[offset]&15)*4
            total=struct.unpack_from('!H',b,offset+2)[0]
            if version!=4 or ihl<20 or total<ihl: raise ValueError('IPv4 头部无效')
            need(offset,ihl); end=min(len(b),offset+total)
            if offset+total>len(b): p.warning='IPv4 数据被截断'
            frag=struct.unpack_from('!H',b,offset+6)[0]; next_header=b[offset+9]
            p.ip_version=4;p.source=str(ipaddress.ip_address(b[offset+12:offset+16]));p.destination=str(ipaddress.ip_address(b[offset+16:offset+20]))
            add('IPv4',源地址=p.source,目的地址=p.destination,头长=ihl,总长=total,TTL=b[offset+8],上层协议=next_header,分片偏移=(frag&8191)*8,MF=bool(frag&8192))
            offset+=ihl
            if frag&0x3fff:
                p.info='IPv4 分片，未进行 IP 重组';p.warning=p.info;return p
        elif ether==0x86dd:
            need(offset,40)
            if b[offset]>>4!=6: raise ValueError('IPv6 版本无效')
            plen=struct.unpack_from('!H',b,offset+4)[0];end=min(len(b),offset+40+plen)
            if offset+40+plen>len(b):p.warning='IPv6 数据被截断'
            p.ip_version=6;p.source=str(ipaddress.ip_address(b[offset+8:offset+24]));p.destination=str(ipaddress.ip_address(b[offset+24:offset+40]))
            next_header=b[offset+6];add('IPv6',源地址=p.source,目的地址=p.destination,载荷长度=plen,下一头部=next_header,跳数限制=b[offset+7]);offset+=40
            for _ in range(12):
                if next_header not in (0,43,44,51,60):break
                need(offset,2,end);nh=b[offset]
                if next_header==44:
                    need(offset,8,end);fragment=struct.unpack_from('!H',b,offset+2)[0]
                    if fragment&0xfff9:
                        p.info='IPv6 分片，未进行 IP 重组';p.warning=p.info;return p
                    size=8
                else: size=(b[offset+1]+2)*4 if next_header==51 else (b[offset+1]+1)*8
                need(offset,size,end);p.details.append(('IPv6 扩展头',{'类型':next_header,'长度':size}));offset+=size;next_header=nh
            else: raise ValueError('IPv6 扩展头数量超过限制')
        else:
            p.info=f'未支持的链路协议 0x{ether:04x}';return p
        if next_header==6:
            need(offset,20,end);p.sport,p.dport,p.sequence,ack=struct.unpack_from('!HHII',b,offset)
            size=(b[offset+12]>>4)*4
            if size<20:raise ValueError('TCP 头长小于 20')
            need(offset,size,end);p.flags=b[offset+13];p.payload=b[offset+size:end]
            names=[n for bit,n in ((1,'FIN'),(2,'SYN'),(4,'RST'),(8,'PSH'),(16,'ACK'),(32,'URG'),(64,'ECE'),(128,'CWR')) if p.flags&bit]
            add('TCP',源端口=p.sport,目的端口=p.dport,序号=p.sequence,确认号=ack,标志=' '.join(names),窗口=struct.unpack_from('!H',b,offset+14)[0],头长=size,载荷长度=len(p.payload))
            p.info=f'{p.sport} → {p.dport} [{" ".join(names)}] Seq={p.sequence} Len={len(p.payload)}'
            payload=p.payload
            line=payload.split(b'\r\n',1)[0]
            if (line.startswith(b'HTTP/1.') or any(line.startswith(m+b' ') for m in (b'GET',b'POST',b'HEAD',b'PUT',b'DELETE',b'OPTIONS',b'PATCH',b'CONNECT',b'TRACE'))):
                text=line[:300].decode('utf-8',errors='replace');add('HTTP',首行=text,识别依据='明文消息起始特征，非端口推断');p.info=text
            elif len(payload)>=5 and payload[0] in (20,21,22,23) and payload[1]==3 and payload[2]<=4:
                length=struct.unpack_from('!H',payload,3)[0]
                if 0<length<=18432:
                    add('TLS',记录类型=payload[0],兼容版本=f'0x{payload[1:3].hex()}',记录长度=length,说明='仅识别记录头，不解密；此字段不代表协商版本');p.info=f'TLS record type={payload[0]} length={length}'
        elif next_header==17:
            need(offset,8,end);p.sport,p.dport,size=struct.unpack_from('!HHH',b,offset)
            if size<8:raise ValueError('UDP 长度小于 8')
            if offset+size>end:p.warning='UDP 数据被截断'
            p.payload=b[offset+8:min(end,offset+size)];add('UDP',源端口=p.sport,目的端口=p.dport,长度=size);p.info=f'{p.sport} → {p.dport} Len={len(p.payload)}'
            if 53 in (p.sport,p.dport) and len(p.payload)>=12:
                try:
                    ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',p.payload)
                    values={'事务ID':hex(ident),'响应':bool(flags&0x8000),'问题数':qd,'回答数':an,'返回码':flags&15}
                    if qd:
                        name,pos=dns_name(p.payload,12)
                        if pos+4>len(p.payload):raise ValueError('DNS 问题截断')
                        kind,cls=struct.unpack_from('!HH',p.payload,pos);values.update({'查询名':name,'查询类型':kind,'查询类':cls})
                    add('DNS',**values);p.info=f'DNS {"响应" if flags&0x8000 else "查询"} {values.get("查询名","")}'
                except ValueError as e:p.warning='DNS 解析失败：'+str(e)
        elif next_header in (1,58):
            need(offset,4,end);proto='ICMP' if next_header==1 else 'ICMPv6';add(proto,类型=b[offset],代码=b[offset+1]);p.info=f'Type={b[offset]} Code={b[offset+1]}';p.payload=b[offset+4:end]
        else:p.info=f'未解析的 IP 上层协议 {next_header}'
    except (ValueError,struct.error) as e:
        p.warning=str(e);p.info=p.info or str(e)
    if len(raw.data)<raw.wire_length:p.warning=(p.warning+'；' if p.warning else '')+'抓取长度小于线上长度'
    return p

def hexdump(data):
    lines=[]
    for i in range(0,len(data),16):
        part=data[i:i+16];lines.append(f'{i:04x}  {" ".join(f"{v:02x}" for v in part):47}  '+''.join(chr(v) if 32<=v<127 else '.' for v in part))
    return '\n'.join(lines)
