# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.cli import audit_output as audit

if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    result = audit(parser.parse_args().output)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")
