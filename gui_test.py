"""Integration checks using real Tk widgets, real Npcap and localhost traffic."""
import json
import tempfile
import time
import tkinter as tk
from pathlib import Path
from unittest.mock import patch
from sniffer.gui import App,make_root
from sniffer.capture import RawPacket

def pump(root,seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:root.update();time.sleep(.01)

def main():
    root=make_root();root.withdraw();app=App(root);checks={}
    try:
        app.bpf.set('tcp port 8088 or udp port 53535');app.start();pump(root,.6);app.demo();pump(root,2.5);app.stop();pump(root,.5)
        checks['live_gui_capture']=app.total>0 and app.session is None
        total=app.total;app.expression.set('http');app.apply_filter()
        checks['display_filter_http']=len(app.table.get_children())>=6 and all(app.records[int(k)].protocol=='HTTP' for k in app.table.get_children())
        checks['filter_preserves_packets']=app.total==total and len(app.records)==total
        first=app.table.get_children()[0];app.table.selection_set(first);app.select()
        checks['details_and_hex']=bool(app.fields.get_children()) and '47 45 54' in app.hex.get('1.0','end')
        app.follow();pump(root,.1);checks['tcp_stream_window']=bool(app.open_streams)
        for window in app.open_streams:window.destroy()
        with patch('sniffer.gui.messagebox.showerror') as popup:
            app.expression.set('tcp and');app.apply_filter();checks['invalid_filter_message']=popup.called
        app.expression.set('');app.apply_filter()
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'saved.pcap';app.save(target);before=[p.raw.data for p in app.records.values()];app.load(target)
            checks['gui_save_load']=before==[p.raw.data for p in app.records.values()]
        app.clear();app.MAX_PACKETS=10;app.MAX_BYTES=100
        for i in range(30):app.ingest(RawPacket(1,b'\x00'*20,20,1))
        checks['bounded_store']=len(app.records)==5 and app.evicted==25 and app.bytes==100
        checks['rendered_rows_evicted']=len(app.table.get_children())==5
        app.clear();checks['clear_resets_all']=not app.records and not app.table.get_children() and app.total==0
        result={'checks':checks,'passed':all(checks.values())};Path('evidence/gui_results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,indent=2));assert result['passed']
    finally:
        if app.session:app.session.stop();app.session.thread.join(3)
        root.destroy()

if __name__=='__main__':main()
