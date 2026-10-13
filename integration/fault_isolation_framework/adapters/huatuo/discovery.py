# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import datetime as dt, http.server, json, re, threading
from pathlib import Path


def parse_timestamp(value):
    value = value.replace("Z", "+00:00")
    # Python 3.8 accepts microseconds but not Docker's nanosecond timestamps.
    value = re.sub(r"(\.\d{6})\d+([+-]\d{2}:\d{2})$", r"\1\2", value)
    return dt.datetime.fromisoformat(value)


class PodFixture(http.server.BaseHTTPRequestHandler):
    containers = {}
    fail_requests = False

    def do_GET(self):
        if self.path != "/pods":
            self.send_error(404)
            return
        if self.fail_requests:
            self.send_error(503)
            return
        items = []
        for container_id, started_at in list(self.containers.items()):
            items.append(
                {
                    "metadata": {
                        "name": "memsnapshot-acceptance-" + container_id[:12],
                        "namespace": "default",
                        "uid": "memsnapshot-acceptance-" + container_id,
                    },
                    "spec": {
                        "hostname": "memsnapshot-acceptance",
                        "containers": [
                            {"name": "workload", "image": "local/acceptance"}
                        ],
                    },
                    "status": {
                        "phase": "Running",
                        "qosClass": "Guaranteed",
                        "containerStatuses": [
                            {
                                "name": "workload",
                                "containerID": f"docker://{container_id}",
                                "state": {"running": {"startedAt": started_at}},
                            }
                        ],
                    },
                }
            )
        data = json.dumps(
            {"kind": "PodList", "apiVersion": "v1", "items": items}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


class Discovery:
    def __init__(self, driver):
        self.driver = driver
        self.server = None
        self.created_config = None

    def start(self):
        PodFixture.containers = {}
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PodFixture)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        paths = [
            Path("/var/lib/kubelet/config.yaml"),
            Path("/var/lib/kubelet/ack-managed-config.yaml"),
            Path("/etc/kubernetes/kubelet/config.json"),
        ]
        if not any(p.exists() for p in paths):
            p = paths[-1]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                json.dumps(
                    dict(
                        cgroupDriver=self.driver,
                        containerRuntimeEndpoint="unix:///var/run/docker.sock",
                    )
                )
            )
            self.created_config = p

    def register(self, target):
        PodFixture.containers[target["cid"]] = (
            dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        )

    def cleanup(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.created_config:
            self.created_config.unlink()
