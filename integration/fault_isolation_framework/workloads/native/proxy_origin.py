# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Deterministic HTTP origin for a real mitmproxy reverse proxy."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SMALL=b'huatuo-business-body\n'*64
LARGE=b'huatuo-pressure-body\n'*(1048576//21)


class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'

    def do_GET(self):
        body=LARGE if self.path=='/large' else SMALL
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

    def log_message(self,*args):pass


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,required=True);a=p.parse_args()
    ThreadingHTTPServer(('127.0.0.1',a.port),Handler).serve_forever()
