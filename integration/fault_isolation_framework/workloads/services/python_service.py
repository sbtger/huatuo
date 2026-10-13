"""CPython business fixture; default GC remains enabled and no census is requested."""
import hashlib, json, os, platform, sys, threading, time, mmap, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXPECTED = "feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d\n"
TEMPLATE = bytes(i % 251 for i in range(128 * 1024))
phase = "warmup"
completed = 0
seq = 0
total = 0
ticks = 0
lock = threading.Lock()
retained = [
    bytearray(1024 * 1024) for _ in range(int(sys.argv[1]) if len(sys.argv) > 1 else 32)
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        global phase, seq, total
        if self.path.startswith("/txn?"):
            n = int(
                urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)["seq"][0]
            )
            with lock:
                if n != seq + 1:
                    self.send_error(409)
                    return
                seq = n
                total += n * 13
            self.state()
            return
        if self.path != "/phase":
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 1 <= size <= 128:
            self.send_error(400)
            return
        value = self.rfile.read(size).decode()
        with lock:
            phase = value
        self.send_response(204)
        self.end_headers()

    def state(self):
        with lock:
            body = json.dumps(
                {"seq": seq, "total": total, "ticks": ticks, "completed": completed}
            ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global completed
        if self.path == "/state":
            self.state()
            return
        if self.path == "/stats":
            with lock:
                body = json.dumps({"completed": completed}).encode()
        elif self.path == "/work":
            with lock:
                ordinal = completed
            data = bytearray(TEMPLATE)
            extra = bytearray((ordinal % 64) * 8192)
            for at in range(0, len(extra), 4096):
                extra[at] = 1
            for _ in range(4):
                digest = hashlib.sha256(data).hexdigest()
            body = (digest + "\n").encode()
            with lock:
                completed += 1
        else:
            self.send_error(404)
            return
        with lock:
            current = phase
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Test-Phase", current)
        self.end_headers()
        self.wfile.write(body)


def background():
    global ticks
    chunks = []
    while True:
        try:
            with open("/control/target_mb") as stream:
                target = int(stream.read())
            while len(chunks) < target:
                chunk = mmap.mmap(-1, 1 << 20)
                chunk[::4096] = b"1" * 256
                chunks.append(chunk)
            while len(chunks) > target:
                chunks.pop().close()
        except FileNotFoundError:
            pass
        with lock:
            ticks += 1
        time.sleep(0.1)


threading.Thread(target=background, daemon=True).start()
server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(
    json.dumps(
        {
            "pid": os.getpid(),
            "url": "http://127.0.0.1:" + str(server.server_port),
            "language": "python",
            "runtime": "CPython" + platform.python_version(),
            "expected_body": EXPECTED,
            "heap_mib": len(retained),
        }
    ),
    flush=True,
)
server.serve_forever()
