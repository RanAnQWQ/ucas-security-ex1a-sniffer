"""Tk front end. Only the Tk thread touches widgets and the retained store."""
import argparse
import collections
import datetime
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .capture import Npcap, CaptureSession
from .protocols import decode, hexdump
from .filters import compile_filter, HELP
from .streams import stream_text
from .pcapio import read_pcap, write_pcap

class App:
    MAX_PACKETS=5000
    MAX_BYTES=16*1024*1024
    def __init__(self, root):
        self.root=root;root.title('澄流 · 网络嗅探器 | 实验 1A');root.geometry('1280x850');root.minsize(1000,700)
        self.records=collections.OrderedDict();self.next_id=1;self.bytes=0;self.evicted=0;self.total=0;self.session=None;self.stopping=False
        self.predicate=lambda p:True;self.devices=[];self.open_streams=[];self.last_error='';self.counts=collections.Counter();self.demo_events=queue.Queue();self.demo_running=False
        style=ttk.Style();style.theme_use('clam')
        style.configure('.',font=('Microsoft YaHei UI',10))
        style.configure('Treeview',rowheight=27,background='#ffffff',fieldbackground='#ffffff',foreground='#172b42')
        style.configure('Treeview.Heading',font=('Microsoft YaHei UI',10,'bold'),background='#e8eef5')
        style.configure('Title.TLabel',font=('Microsoft YaHei UI',20,'bold'),foreground='#173a57')
        style.configure('Accent.TButton',foreground='white',background='#167d8d')
        base=ttk.Frame(root,padding=14);base.pack(fill='both',expand=True)
        header=ttk.Frame(base);header.pack(fill='x')
        ttk.Label(header,text='澄流  /  网络嗅探器',style='Title.TLabel').pack(side='left')
        ttk.Label(header,text='EX1A · 安然 · 202628015059001',foreground='#64748b').pack(side='right')
        controls=ttk.Frame(base);controls.pack(fill='x',pady=(12,6))
        ttk.Label(controls,text='网卡').pack(side='left')
        self.adapter=ttk.Combobox(controls,state='readonly',width=57);self.adapter.pack(side='left',padx=6)
        self.refresh_btn=ttk.Button(controls,text='刷新',command=self.refresh);self.refresh_btn.pack(side='left')
        self.start_btn=ttk.Button(controls,text='开始抓包',style='Accent.TButton',command=self.start);self.start_btn.pack(side='left',padx=(12,6))
        self.stop_btn=ttk.Button(controls,text='停止',command=self.stop,state='disabled');self.stop_btn.pack(side='left')
        ttk.Button(controls,text='清空',command=self.clear).pack(side='left',padx=6)
        self.bpf=tk.StringVar(value='');row=ttk.Frame(base);row.pack(fill='x',pady=4)
        ttk.Label(row,text='抓包过滤 BPF').pack(side='left');self.bpf_entry=ttk.Entry(row,textvariable=self.bpf,width=55);self.bpf_entry.pack(side='left',padx=6)
        ttk.Label(row,text='例：tcp or udp  /  host 127.0.0.1',foreground='#64748b').pack(side='left')
        self.expression=tk.StringVar();row=ttk.Frame(base);row.pack(fill='x',pady=4)
        ttk.Label(row,text='显示过滤').pack(side='left');entry=ttk.Entry(row,textvariable=self.expression,width=59);entry.pack(side='left',padx=6);entry.bind('<Return>',lambda e:self.apply_filter())
        ttk.Button(row,text='应用',command=self.apply_filter).pack(side='left')
        self.quick=ttk.Combobox(row,state='readonly',values=['全部','tcp','udp','http','dns','tls','ipv4','ipv6','icmp','arp'],width=9);self.quick.current(0);self.quick.pack(side='left',padx=6);self.quick.bind('<<ComboboxSelected>>',self.quick_filter)
        ttk.Button(row,text='过滤语法',command=lambda:messagebox.showinfo('显示过滤语法',HELP+'\n优先级：not > and > or，支持括号。\n字段：host/src/dst/port/sport/dport。\nHTTP/DNS/TLS 根据内容识别，非单纯按端口。')).pack(side='left')
        toolbar=ttk.Frame(base);toolbar.pack(fill='x',pady=(6,8))
        ttk.Button(toolbar,text='打开 PCAP',command=self.load).pack(side='left')
        ttk.Button(toolbar,text='保存全部保留包',command=self.save).pack(side='left',padx=6)
        ttk.Button(toolbar,text='追踪选中 TCP 流',command=self.follow).pack(side='left')
        ttk.Button(toolbar,text='生成本机演示流量',command=self.demo).pack(side='left',padx=6)
        self.summary=tk.StringVar(value='就绪');ttk.Label(toolbar,textvariable=self.summary,foreground='#146777').pack(side='right')
        panes=ttk.Panedwindow(base,orient='vertical');panes.pack(fill='both',expand=True)
        upper=ttk.Frame(panes);panes.add(upper,weight=3)
        columns=('id','time','src','dst','protocol','len','info')
        self.table=ttk.Treeview(upper,columns=columns,show='headings',selectmode='browse')
        for key,title,width in zip(columns,['序号','时间','源地址','目的地址','协议','字节','摘要'],[55,112,165,165,75,60,400]):
            self.table.heading(key,text=title);self.table.column(key,width=width,minwidth=45,stretch=key in ('src','dst','info'))
        vs=ttk.Scrollbar(upper,orient='vertical',command=self.table.yview);hs=ttk.Scrollbar(upper,orient='horizontal',command=self.table.xview)
        self.table.configure(yscrollcommand=vs.set,xscrollcommand=hs.set);self.table.grid(row=0,column=0,sticky='nsew');vs.grid(row=0,column=1,sticky='ns');hs.grid(row=1,column=0,sticky='ew');upper.rowconfigure(0,weight=1);upper.columnconfigure(0,weight=1)
        for proto,color in [('TCP','#edf5ff'),('HTTP','#e5f6ef'),('UDP','#f1edfc'),('DNS','#e7f7fa'),('TLS','#fff4df'),('ARP','#fff1e9')]:self.table.tag_configure(proto,background=color)
        self.table.bind('<<TreeviewSelect>>',self.select)
        lower=ttk.Panedwindow(panes,orient='horizontal');panes.add(lower,weight=2)
        left=ttk.Labelframe(lower,text='协议字段',padding=6);right=ttk.Labelframe(lower,text='原始字节 / Hex + ASCII',padding=6);lower.add(left,weight=1);lower.add(right,weight=1)
        self.fields=ttk.Treeview(left,columns=('value',),show='tree headings');self.fields.heading('#0',text='字段');self.fields.heading('value',text='值');self.fields.column('#0',width=150);self.fields.column('value',width=290)
        fs=ttk.Scrollbar(left,command=self.fields.yview);self.fields.configure(yscrollcommand=fs.set);fs.pack(side='right',fill='y');self.fields.pack(fill='both',expand=True)
        self.hex=tk.Text(right,wrap='none',font=('Consolas',10),background='#14293d',foreground='#e2edf7',borderwidth=0)
        sy=ttk.Scrollbar(right,command=self.hex.yview);sx=ttk.Scrollbar(right,orient='horizontal',command=self.hex.xview);self.hex.configure(yscrollcommand=sy.set,xscrollcommand=sx.set,state='disabled');sy.pack(side='right',fill='y');sx.pack(side='bottom',fill='x');self.hex.pack(fill='both',expand=True)
        self.status=tk.StringVar(value='选择网卡后开始抓包；演示建议选择 Loopback，过滤 tcp port 8088 or udp port 53535。')
        ttk.Label(base,textvariable=self.status,wraplength=1200,foreground='#475569').pack(fill='x',pady=(8,0))
        root.protocol('WM_DELETE_WINDOW',self.close);self.refresh();root.after(50,self.poll)

    def refresh(self):
        if self.session:return
        try:
            self.devices=Npcap().devices();self.adapter['values']=[f'{desc}  [{name.rsplit("_",1)[-1]}]' for name,desc in self.devices]
            if self.devices:self.adapter.current(next((i for i,(n,d) in enumerate(self.devices) if 'Loopback' in n),0))
        except Exception as e:self.status.set(str(e));self.last_error=str(e)

    def fail(self,title,e):
        self.last_error=str(e);self.status.set(title+'：'+str(e));messagebox.showerror(title,str(e),parent=self.root)

    def start(self):
        if self.session:return
        i=self.adapter.current()
        if i<0:self.fail('无法开始','请选择可用网卡');return
        if self.records:
            if not messagebox.askyesno('新建抓包','开始新的抓包会清空当前保留的数据，是否继续？',parent=self.root):return
            self.clear()
        self.session=CaptureSession(self.devices[i][0],self.bpf.get());self.session.start();self.stopping=False
        self.start_btn['state']='disabled';self.stop_btn['state']='normal';self.adapter['state']='disabled';self.bpf_entry['state']='disabled';self.refresh_btn['state']='disabled';self.status.set('正在打开网卡并编译 BPF 过滤器…')

    def stop(self):
        if self.session:self.session.stop();self.stopping=True;self.stop_btn['state']='disabled';self.status.set('正在停止并处理队列中的剩余数据…')

    def clear(self):
        if self.session:self.status.set('请先停止抓包，再清空。');return
        self.records.clear();self.counts.clear();self.bytes=0;self.total=0;self.evicted=0;self.next_id=1
        self.table.delete(*self.table.get_children());self.fields.delete(*self.fields.get_children());self.set_text(self.hex,'');self.update_summary()

    @staticmethod
    def set_text(widget,text):widget.configure(state='normal');widget.delete('1.0','end');widget.insert('1.0',text);widget.configure(state='disabled')

    def insert_row(self,key,p):
        try:stamp=datetime.datetime.fromtimestamp(p.raw.timestamp).strftime('%H:%M:%S.%f')[:-3]
        except (ValueError,OSError,OverflowError):stamp=str(p.raw.timestamp)
        self.table.insert('','end',iid=str(key),values=(key,stamp,p.source,p.destination,p.protocol,p.raw.wire_length,p.info),tags=(p.protocol,))

    def ingest(self,raw):
        p=decode(raw);key=self.next_id;self.next_id+=1;self.records[key]=p;self.bytes+=len(raw.data);self.total+=1;self.counts[p.protocol]+=1
        if self.predicate(p):self.insert_row(key,p)
        while len(self.records)>self.MAX_PACKETS or self.bytes>self.MAX_BYTES:
            old,packet=self.records.popitem(last=False);self.bytes-=len(packet.raw.data);self.evicted+=1
            if self.table.exists(str(old)):self.table.delete(str(old))

    def update_summary(self):
        self.summary.set(f'总接收 {self.total}  ·  保留 {len(self.records)}  ·  显示 {len(self.table.get_children())}  ·  淘汰 {self.evicted}')

    def poll(self):
        while not self.demo_events.empty():
            error=self.demo_events.get_nowait();self.demo_running=False
            if error:self.fail('演示流量生成失败',error)
        if self.session:
            session=self.session
            for _ in range(160):
                try:self.ingest(session.packets.get_nowait())
                except queue.Empty:break
            while not session.events.empty():
                kind,message=session.events.get_nowait()
                if kind=='error':self.fail('抓包失败',message)
                elif kind=='ready':self.status.set('实时抓包中 · '+str(message))
            if not session.running and session.packets.empty():
                self.status.set(f'已停止 | 应用队列丢包 {session.queue_drops} | 驱动统计 {session.driver_stats} | 协议分布 {dict(self.counts)}')
                self.session=None;self.start_btn['state']='normal';self.stop_btn['state']='disabled';self.adapter['state']='readonly';self.bpf_entry['state']='normal';self.refresh_btn['state']='normal'
            self.update_summary()
        self.root.after(50,self.poll)

    def quick_filter(self,event=None):self.expression.set('' if self.quick.get()=='全部' else self.quick.get());self.apply_filter()

    def apply_filter(self):
        try:predicate=compile_filter(self.expression.get())
        except ValueError as e:self.fail('显示过滤无效',e);return
        self.predicate=predicate;self.table.delete(*self.table.get_children())
        for key,p in self.records.items():
            if predicate(p):self.insert_row(key,p)
        self.update_summary();self.status.set('显示过滤已应用；原始保留数据未删除。')

    def select(self,event=None):
        selected=self.table.selection()
        if not selected:return
        p=self.records.get(int(selected[0]))
        if p is None:return
        self.fields.delete(*self.fields.get_children())
        root=self.fields.insert('','end',text='Frame',open=True)
        for key,value in {'时间戳':f'{p.raw.timestamp:.6f}','线上长度':p.raw.wire_length,'抓取长度':len(p.raw.data),'链路类型':p.raw.linktype,'注意':p.warning or '无'}.items():self.fields.insert(root,'end',text=key,values=(value,))
        for layer,values in p.details:
            parent=self.fields.insert('','end',text=layer,open=True)
            for key,value in values.items():self.fields.insert(parent,'end',text=key,values=(value,))
        self.set_text(self.hex,hexdump(p.raw.data))

    def follow(self):
        selected=self.table.selection();p=self.records.get(int(selected[0])) if selected else None
        if p is None or p.flow_key is None:self.status.set('请先选择一个 TCP 数据包。');return
        packets=[v for v in self.records.values() if v.flow_key==p.flow_key]
        window=tk.Toplevel(self.root);window.title('TCP 双向流 / '+str(p.flow_key));window.geometry('1050x650')
        text=tk.Text(window,wrap='word',font=('Consolas',11),padx=14,pady=12);scroll=ttk.Scrollbar(window,command=text.yview);text.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');text.pack(fill='both',expand=True);self.set_text(text,stream_text(packets));self.open_streams.append(window)

    def load(self,path=None):
        if self.session:self.status.set('请先停止抓包，再打开文件。');return
        path=path or filedialog.askopenfilename(filetypes=[('经典 PCAP','*.pcap'),('全部文件','*.*')])
        if not path:return
        try:raws=read_pcap(path)
        except Exception as e:self.fail('打开失败',e);return
        self.clear()
        for raw in raws:self.ingest(raw)
        self.update_summary();self.status.set(f'已读取 {path}；文件内 {len(raws)} 包，保留 {len(self.records)} 包。')

    def save(self,path=None):
        if not self.records:self.status.set('没有可保存的数据包。');return
        path=path or filedialog.asksaveasfilename(defaultextension='.pcap',filetypes=[('经典 PCAP','*.pcap')])
        if not path:return
        try:write_pcap(path,[p.raw for p in self.records.values()]);self.status.set('已保存全部保留包（不受显示过滤影响）：'+str(path))
        except Exception as e:self.fail('保存失败',e)

    def demo(self):
        from .traffic import generate
        if self.demo_running:self.status.set('本机演示流量仍在生成，请稍候。');return
        self.demo_running=True
        def run():
            try:generate();self.demo_events.put('')
            except Exception as e:self.demo_events.put(str(e))
        threading.Thread(target=run,daemon=True,name='demo-traffic').start()
        self.status.set('正在生成本机 HTTP 和 UDP 流量；请选择 Loopback，BPF 使用 tcp port 8088 or udp port 53535。')

    def close(self):
        if self.session:
            self.session.stop();self.root.after(50,self._close_wait)
        else:self.root.destroy()
    def _close_wait(self):
        if self.session and self.session.running:self.root.after(50,self._close_wait)
        else:self.root.destroy()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--open',dest='pcap');args=parser.parse_args()
    root=tk.Tk();app=App(root)
    if args.pcap:root.after(100,lambda:app.load(args.pcap))
    root.mainloop()
