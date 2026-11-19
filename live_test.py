"""Run locally with Npcap installed: python live_test.py. Writes evidence only."""
import json
import queue
import socket
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sniffer.capture import Npcap,CaptureSession
from sniffer.protocols import decode
from sniffer.pcapio import write_pcap,read_pcap
from sniffer.streams import stream_text
from sniffer.traffic import generate

def wait_ready(session):
    end=time.monotonic()+5
    while time.monotonic()<end:
        try:kind,message=session.events.get(timeout=.2)
        except queue.Empty:continue
        if kind=='ready':return
        if kind=='error':raise RuntimeError(message)
    raise RuntimeError('抓包启动超时')

def finish(session):
    time.sleep(.5);session.stop();session.thread.join(3)
    assert not session.running,'停止超时'
    errors=[]
    while not session.events.empty():
        event=session.events.get_nowait()
        if event[0]=='error':errors.append(event[1])
    assert not errors,errors
    packets=[]
    while not session.packets.empty():packets.append(session.packets.get_nowait())
    return packets

def main():
    folder=Path(__file__).parent/'evidence';folder.mkdir(exist_ok=True)
    api=Npcap();results={'npcap':api.version,'time':datetime.now(timezone(timedelta(hours=8))).isoformat(),'checks':{}}
    session=CaptureSession(r'\Device\NPF_Loopback','tcp port 8088 or udp port 53535');session.start();wait_ready(session)
    generate()
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as excluded:
        for _ in range(3):excluded.sendto(b'EX1A_MUST_BE_FILTERED_OUT',('127.0.0.1',53536))
    raws=finish(session);packets=[decode(p) for p in raws]
    checks=results['checks'];checks['localhost_capture']=len(packets)>0
    checks['timestamp_valid']=all(abs(time.time()-p.raw.timestamp)<60 for p in packets)
    checks['http_request']=any(p.protocol=='HTTP' and p.info.startswith('GET ') for p in packets)
    checks['http_response']=any(p.protocol=='HTTP' and p.info.startswith('HTTP/1.1 200') for p in packets)
    checks['udp_capture']=sum(p.protocol=='UDP' for p in packets)>=5
    checks['bpf_only_requested_ports']=all((8088 in (p.sport,p.dport) or 53535 in (p.sport,p.dport)) and b'EX1A_MUST_BE_FILTERED_OUT' not in p.raw.data for p in packets)
    checks['clean_shutdown']=not session.running
    tcp=[p for p in packets if p.flow_key];flow=[p for p in packets if p.flow_key==tcp[0].flow_key]
    stream=stream_text(flow);checks['stream_request_and_response']='GET /experiment/' in stream and 'Hello EX1A!' in stream
    write_pcap(folder/'demo.pcap',raws);checks['pcap_exact_roundtrip']=all(a.data==b.data and abs(a.timestamp-b.timestamp)<.000002 for a,b in zip(raws,read_pcap(folder/'demo.pcap')))
    results['packets']=len(packets);results['protocol_counts']={proto:sum(p.protocol==proto for p in packets) for proto in sorted({p.protocol for p in packets})}
    results['queue_drops']=session.queue_drops;results['driver_stats']=session.driver_stats
    (folder/'tcp_stream.txt').write_text(stream,encoding='utf-8',newline='\n')
    invalid=CaptureSession(r'\Device\NPF_Loopback','this is invalid bpf !!!');invalid.start();invalid.thread.join(3)
    checks['invalid_bpf_rejected']=any(kind=='error' for kind,_ in list(invalid.events.queue)) and not invalid.running
    for i in range(3):
        repeated=CaptureSession(r'\Device\NPF_Loopback','udp port 53535');repeated.start();wait_ready(repeated);finish(repeated)
    checks['repeat_start_stop']=True
    wifi=next((name for name,desc in api.devices() if 'AX211' in desc),None)
    if wifi:
        session=CaptureSession(wifi,'udp dst port 49327');session.start();wait_ready(session)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            for i in range(5):s.sendto(b'EX1A_WIFI_VALIDATION',('192.0.2.1',49327));time.sleep(.1)
        raw_wifi=finish(session);checks['wifi_capture']=sum(b'EX1A_WIFI_VALIDATION' in r.data for r in raw_wifi)>=5
    results['passed']=all(checks.values());(folder/'live_results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(results,ensure_ascii=False,indent=2));assert results['passed']

if __name__=='__main__':main()
