"""Bounded, directional TCP sequence reconstruction from captured segments.

Missing bytes remain explicit holes. Retransmissions are deduplicated and
conflicting overlaps reported. This is not a complete TCP state machine.
"""
def relative_sequence(seq, anchor):
    return ((seq-anchor+2**31)%2**32)-2**31

def reconstruct(packets, limit=1024*1024):
    groups={}; base_time=packets[0].raw.timestamp if packets else 0
    timeline=[]
    for p in packets:
        if 'TCP' not in p.layers:continue
        direction=f'[{p.source}]:{p.sport} → [{p.destination}]:{p.dport}'
        timeline.append(f'{p.raw.timestamp-base_time:9.6f}s  {direction}  seq={p.sequence} flags=0x{p.flags:02x} bytes={len(p.payload)}')
        if p.payload:groups.setdefault(direction,[]).append(((p.sequence+bool(p.flags&2))%2**32,p.payload))
    results=[]
    for direction,segments in groups.items():
        anchor=segments[0][0]; cells={};duplicates=0;conflicts=0;omitted=0
        for seq,data in segments:
            start=relative_sequence(seq,anchor)
            for i,byte in enumerate(data):
                position=start+i
                if position in cells:
                    duplicates+=1
                    if cells[position]!=byte:conflicts+=1
                elif len(cells)<limit:cells[position]=byte
                else:omitted+=1
        chunks=[]; previous=None; current=bytearray(); gaps=0
        for position in sorted(cells):
            if previous is not None and position!=previous+1:
                chunks.append(bytes(current));current.clear();gap=position-previous-1;gaps+=gap
                chunks.append(f'\n[缺失 {gap} 字节，未补造内容]\n')
            current.append(cells[position]);previous=position
        if current:chunks.append(bytes(current))
        results.append({'direction':direction,'chunks':chunks,'unique_bytes':len(cells),'duplicate_bytes':duplicates,'conflicting_bytes':conflicts,'missing_bytes':gaps,'omitted_bytes':omitted})
    return results,timeline

def stream_text(packets):
    results,timeline=reconstruct(packets)
    lines=['TCP 双向流分析','仅重组当前保留的数据；中途开始抓包无法判断此前缺失的数据。',
           '同一端点对在不同时间复用连接时仍归为一组；序号跨度需小于 2^31。','']
    for r in results:
        lines.extend([r['direction'],f"唯一字节 {r['unique_bytes']} | 重复字节 {r['duplicate_bytes']} | 冲突字节 {r['conflicting_bytes']} | 缺口 {r['missing_bytes']} | 超限省略 {r['omitted_bytes']}"])
        lines.extend(c.decode('utf-8',errors='replace') if isinstance(c,bytes) else c for c in r['chunks'])
        lines.append('')
    lines+=['时序记录（基于抓取时间戳）',*timeline]
    return '\n'.join(lines)
