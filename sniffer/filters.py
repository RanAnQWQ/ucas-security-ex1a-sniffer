"""Small recursive-descent display filter. No eval, shell, or executable syntax."""
import re
import ipaddress

HELP = '例：tcp and port 8088 | http or dns | ipv6 | host 127.0.0.1 | not udp | src 127.0.0.1 and tcp'
PROTOCOLS = {'ethernet':'Ethernet','arp':'ARP','ipv4':'IPv4','ip':'IPv4','ipv6':'IPv6','tcp':'TCP','udp':'UDP','icmp':'ICMP','icmpv6':'ICMPv6','http':'HTTP','dns':'DNS','tls':'TLS'}

def compile_filter(expression):
    if len(expression)>1024:raise ValueError('过滤表达式过长')
    tokens=re.findall(r'\(|\)|[^\s()]+',expression.lower());pos=0;depth=0
    def atom():
        nonlocal pos,depth
        depth+=1
        if depth>32:raise ValueError('过滤表达式嵌套过深')
        try:
            if pos>=len(tokens):raise ValueError('缺少过滤条件')
            token=tokens[pos];pos+=1
            if token=='not':
                child=atom();return lambda p:not child(p)
            if token=='(':
                child=disjunction()
                if pos>=len(tokens) or tokens[pos]!=')':raise ValueError('缺少右括号')
                pos+=1;return child
            if token in PROTOCOLS:
                proto=PROTOCOLS[token];return lambda p:proto in p.layers
            if token in ('host','src','dst','port','sport','dport'):
                if pos>=len(tokens):raise ValueError(token+' 后缺少值')
                value=tokens[pos];pos+=1
                if token in ('port','sport','dport'):
                    try:value=int(value)
                    except ValueError:raise ValueError('端口必须是整数')
                    if not 0<=value<=65535:raise ValueError('端口范围为 0 到 65535')
                    return lambda p: value in ((p.sport,p.dport) if token=='port' else (p.sport,) if token=='sport' else (p.dport,))
                value=str(ipaddress.ip_address(value))
                return lambda p: value in ((p.source,p.destination) if token=='host' else (p.source,) if token=='src' else (p.destination,))
            raise ValueError('未知过滤条件：'+token)
        finally:depth-=1
    def conjunction():
        nonlocal pos
        children=[atom()]
        while pos<len(tokens) and tokens[pos]=='and':pos+=1;children.append(atom())
        return lambda p:all(f(p) for f in children)
    def disjunction():
        nonlocal pos
        children=[conjunction()]
        while pos<len(tokens) and tokens[pos]=='or':pos+=1;children.append(conjunction())
        return lambda p:any(f(p) for f in children)
    if not tokens:return lambda p:True
    result=disjunction()
    if pos!=len(tokens):raise ValueError('条件之间需要 and 或 or：'+tokens[pos])
    return result
