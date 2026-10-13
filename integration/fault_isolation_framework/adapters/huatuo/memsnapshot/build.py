# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Build plain Agent and a separately identified test-only Go overlay Agent."""
import argparse, hashlib, json, os, subprocess
from pathlib import Path

HELPER = r"""
// Test-only overlay; never included in the shipping Agent.
type memsnapshotFaultSpec struct { PID int `json:"pid"`; Action string `json:"action"`; ID string `json:"id"` }
var memsnapshotFaultSeen sync.Map
func memsnapshotFault(pid int, stage string) memsnapshotFaultSpec {
 var f memsnapshotFaultSpec
 b,err:=os.ReadFile(os.Getenv("HUATUO_MEMSNAP_FAULT_FILE"))
 if err!=nil || json.Unmarshal(b,&f)!=nil || f.PID!=pid { return memsnapshotFaultSpec{} }
 provider:=f.Action=="panic"||f.Action=="cancel"
 if (stage=="provider")!=provider {return memsnapshotFaultSpec{}}
 if _,seen:=memsnapshotFaultSeen.LoadOrStore(f.ID+stage,true);!seen {
  fmt.Fprintf(os.Stderr,"MEMSNAP_FAULT id=%s action=%s pid=%d stage=%s\n",f.ID,f.Action,pid,stage)
 }
 return f
}
func MemsnapshotTestProvider(ctx context.Context,pid int) context.Context {
 f:=memsnapshotFault(pid,"provider")
 switch f.Action {
 case "panic":panic("test-only runtime snapshot panic")
 case "cancel":c,cancel:=context.WithCancel(ctx);cancel();return c
 }
 return ctx
}
func ProcessVMReadv(pid int, localIov []Iovec,remoteIov []RemoteIovec,flags uint)(n int,err error) {
 f:=memsnapshotFault(pid,"read")
 switch f.Action {
 case "efault":return -1,EFAULT
 case "block":select{}
 case "delay":time.Sleep(4*time.Second)
 }
 n,err=memsnapshotRealProcessVMReadv(pid,localIov,remoteIov,flags)
 if f.Action=="short" && err==nil && n>0 {n--}
 if f.Action=="kill_after_read" {fmt.Fprintf(os.Stderr,"MEMSNAP_READ_COMPLETED id=%s n=%d err=%v\n",f.ID,n,err);select{}}
 if f.Action=="mark" {if _,seen:=memsnapshotFaultSeen.LoadOrStore(f.ID+"result",true);!seen {fmt.Fprintf(os.Stderr,"MEMSNAP_READ_RESULT id=%s n=%d err=%v\n",f.ID,n,err)}}
 return
}
"""


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    repo = Path(a.repo).resolve()
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
    if not (repo / "internal/bpf/abi").is_dir():
        run("go", "run", "-mod=vendor", "./build/bpfabi-tool", cwd=repo, env=env)
    run(
        "go",
        "build",
        "-mod=vendor",
        "-o",
        str(out / "agent"),
        "./cmd/huatuo-bamai",
        cwd=repo,
        env=env,
    )
    syscall = repo / "vendor/golang.org/x/sys/unix/zsyscall_linux.go"
    provider = repo / "internal/memsnapshot/collector/provider.go"
    s = syscall.read_text()
    signature = "func ProcessVMReadv("
    assert s.count(signature) == 1, "ProcessVMReadv anchor changed; review the overlay"
    s = s.replace(signature, "func memsnapshotRealProcessVMReadv(")
    s = (
        s.replace(
            "import (",
            'import (\n "context"\n "encoding/json"\n "os"\n "fmt"\n "sync"\n "time"',
            1,
        )
        + HELPER
    )
    q = provider.read_text()
    anchor = "snapshot, err := p.Snapshot(ctx, request)"
    assert q.count(anchor) == 1, "provider anchor changed; review the overlay"
    q = q.replace('"context"', '"context"\n "golang.org/x/sys/unix"').replace(
        anchor, "ctx = unix.MemsnapshotTestProvider(ctx, process.TGID)\n\t" + anchor
    )
    (out / "syscall_overlay.go").write_text(s)
    (out / "provider_overlay.go").write_text(q)
    overlay = {
        "Replace": {
            str(syscall): str(out / "syscall_overlay.go"),
            str(provider): str(out / "provider_overlay.go"),
        }
    }
    (out / "overlay.json").write_text(json.dumps(overlay, indent=2))
    run(
        "gofmt", "-w", str(out / "syscall_overlay.go"), str(out / "provider_overlay.go")
    )
    run(
        "go",
        "build",
        "-mod=vendor",
        "-overlay",
        str(out / "overlay.json"),
        "-o",
        str(out / "agent-fault"),
        "./cmd/huatuo-bamai",
        cwd=repo,
        env=env,
    )
    run(
        "go",
        "build",
        "-o",
        str(out / "business-go"),
        str(Path(__file__).resolve().parents[3] / "workloads/services/main.go"),
        env=env,
    )
    sec = out / "deny_readv.c"
    sec.write_text((Path(__file__).parent / "deny_readv.c").read_text())
    run("cc", "-O2", "-o", str(out / "deny-readv"), str(sec))
    files = {
        name: hashlib.sha256((out / name).read_bytes()).hexdigest()
        for name in ("agent", "agent-fault", "business-go", "deny-readv")
    }
    manifest = {
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, universal_newlines=True
        ).strip(),
        "go": subprocess.check_output(
            ["go", "version"], universal_newlines=True
        ).strip(),
        "sha256": files,
        "test_only_overlay": True,
        "architecture": "linux/amd64",
    }
    (out / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
