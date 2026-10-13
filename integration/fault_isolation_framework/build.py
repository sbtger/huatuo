# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.adapters.huatuo.memsnapshot.build import main

if __name__ == "__main__":
    main()
