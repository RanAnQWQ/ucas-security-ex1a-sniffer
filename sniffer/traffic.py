"""Deterministic localhost traffic. Never captures third-party browsing content."""
import http.client
import http.server
import socket
import threading
import time

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        body=b'Hello EX1A! This is real localhost HTTP traffic.\n'
        self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def generate():
    server=http.server.ThreadingHTTPServer(('127.0.0.1',8088),Handler);server.daemon_threads=True
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        connection=http.client.HTTPConnection('127.0.0.1',8088,timeout=3)
        try:
            for i in range(3):
                connection.request('GET',f'/experiment/{i+1}',headers={'User-Agent':'EX1A-local-demo'})
                response=connection.getresponse();response.read();time.sleep(.15)
        finally:connection.close()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            for i in range(5):udp.sendto(f'EX1A UDP demonstration {i}'.encode(),('127.0.0.1',53535));time.sleep(.05)
    finally:server.shutdown();server.server_close();worker.join(timeout=2)

if __name__=='__main__':generate()
