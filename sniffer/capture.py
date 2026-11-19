"""Windows Npcap ctypes binding. A handle belongs to its capture thread only."""
import ctypes as C
import os
import queue
import threading
import time
from dataclasses import dataclass

class CaptureError(RuntimeError): pass

class Device(C.Structure): pass
Device._fields_ = [('next', C.POINTER(Device)), ('name', C.c_char_p),
                   ('description', C.c_char_p), ('addresses', C.c_void_p), ('flags', C.c_uint)]

class Header(C.Structure):
    # Windows Winsock timeval uses two 32-bit longs, including on Win64.
    _fields_ = [('sec', C.c_int32), ('usec', C.c_int32), ('caplen', C.c_uint32), ('length', C.c_uint32)]
class BPF(C.Structure):
    _fields_ = [('length', C.c_uint), ('instructions', C.c_void_p)]
class Stats(C.Structure):
    _fields_ = [('received', C.c_uint), ('dropped', C.c_uint), ('interface_dropped', C.c_uint), ('captured', C.c_uint)]

@dataclass(frozen=True)
class RawPacket:
    timestamp: float
    data: bytes
    wire_length: int
    linktype: int

class Npcap:
    def __init__(self):
        if os.name != 'nt': raise CaptureError('实时抓包仅支持 Windows + Npcap；其他系统可离线分析 PCAP。')
        folder = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Npcap')
        try:
            self.dll_dir = os.add_dll_directory(folder)
            self.lib = C.CDLL(os.path.join(folder, 'wpcap.dll'))
        except OSError as e:
            raise CaptureError('未能加载 Npcap。请安装与 Python 架构匹配的 Npcap，并检查驱动是否运行。') from e
        def bind(name, args, ret):
            f = getattr(self.lib, name); f.argtypes = args; f.restype = ret
        bind('pcap_lib_version', [], C.c_char_p)
        bind('pcap_findalldevs', [C.POINTER(C.POINTER(Device)), C.c_char_p], C.c_int)
        bind('pcap_freealldevs', [C.POINTER(Device)], None)
        bind('pcap_open_live', [C.c_char_p,C.c_int,C.c_int,C.c_int,C.c_char_p], C.c_void_p)
        bind('pcap_close', [C.c_void_p], None)
        bind('pcap_geterr', [C.c_void_p], C.c_char_p)
        bind('pcap_datalink', [C.c_void_p], C.c_int)
        bind('pcap_compile', [C.c_void_p,C.POINTER(BPF),C.c_char_p,C.c_int,C.c_uint], C.c_int)
        bind('pcap_setfilter', [C.c_void_p,C.POINTER(BPF)], C.c_int)
        bind('pcap_freecode', [C.POINTER(BPF)], None)
        bind('pcap_setnonblock', [C.c_void_p,C.c_int,C.c_char_p], C.c_int)
        bind('pcap_next_ex', [C.c_void_p,C.POINTER(C.POINTER(Header)),C.POINTER(C.POINTER(C.c_ubyte))], C.c_int)
        bind('pcap_stats', [C.c_void_p,C.POINTER(Stats)], C.c_int)

    @property
    def version(self): return self.lib.pcap_lib_version().decode(errors='replace')

    def devices(self):
        head = C.POINTER(Device)(); err = C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(head), err): raise CaptureError(err.value.decode(errors='replace'))
        result = []
        try:
            current = head
            while current:
                dev = current.contents
                result.append((dev.name.decode(), (dev.description or dev.name).decode('utf-8', errors='replace')))
                current = dev.next
        finally: self.lib.pcap_freealldevs(head)
        return result

    def open(self, device, expression=''):
        err = C.create_string_buffer(256)
        handle = self.lib.pcap_open_live(device.encode(), 65535, 0, 100, err)
        if not handle: raise CaptureError(err.value.decode(errors='replace'))
        try:
            if expression.strip():
                program = BPF()
                if self.lib.pcap_compile(handle, C.byref(program), expression.encode(), 1, 0xffffffff):
                    raise CaptureError('BPF 过滤表达式无效：' + self.error(handle))
                try:
                    if self.lib.pcap_setfilter(handle, C.byref(program)): raise CaptureError(self.error(handle))
                finally: self.lib.pcap_freecode(C.byref(program))
            if self.lib.pcap_setnonblock(handle, 1, err): raise CaptureError(err.value.decode(errors='replace'))
            return handle
        except Exception:
            self.lib.pcap_close(handle); raise

    def error(self, handle): return self.lib.pcap_geterr(handle).decode(errors='replace')

    def read(self, handle, linktype):
        header = C.POINTER(Header)(); data = C.POINTER(C.c_ubyte)()
        status = self.lib.pcap_next_ex(handle, C.byref(header), C.byref(data))
        if status == 0: return None
        if status < 0: raise CaptureError(self.error(handle))
        h = header.contents
        if h.caplen > 65535: raise CaptureError('驱动返回的抓取长度异常')
        return RawPacket(h.sec + h.usec / 1e6, C.string_at(data, h.caplen), h.length, linktype)

class CaptureSession:
    """Bounded queue prevents slow rendering from exhausting memory."""
    def __init__(self, device, expression='', capacity=2048):
        self.device, self.expression = device, expression
        self.packets = queue.Queue(maxsize=capacity)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name='npcap-capture')
        self.queue_drops = 0
        self.driver_stats = {}
    def start(self): self.thread.start()
    def stop(self): self.stop_event.set()
    @property
    def running(self): return self.thread.is_alive()
    def _run(self):
        api = None; handle = None
        try:
            api = Npcap(); handle = api.open(self.device, self.expression)
            linktype = api.lib.pcap_datalink(handle)
            if linktype not in (0,1,12,101,108,113,276): raise CaptureError(f'暂不支持链路类型 {linktype}')
            self.events.put(('ready', api.version))
            while not self.stop_event.is_set():
                packet = api.read(handle, linktype)
                if packet is None: self.stop_event.wait(.01); continue
                try: self.packets.put_nowait(packet)
                except queue.Full: self.queue_drops += 1
        except Exception as e: self.events.put(('error', str(e)))
        finally:
            if handle:
                stats = Stats()
                if api.lib.pcap_stats(handle, C.byref(stats)) == 0:
                    self.driver_stats = {'received':stats.received,'dropped':stats.dropped,'interface_dropped':stats.interface_dropped}
                api.lib.pcap_close(handle)
            self.events.put(('stopped', self.driver_stats))
