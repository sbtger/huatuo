# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
def validate_fault(mode, result):
    witnesses = {
        "permission": ("operation not permitted",),
        "efault": ("bad address",),
        "short": (
            "short process memory read",
            "short process memory batch read",
            "short hotspot memory read",
            "short hotspot vector memory read",
            "short cpython process memory read",
            "short read",
        ),
        "panic": ("runtime snapshot panic",),
        "cancel": ("context canceled",),
        "delay": ("context deadline exceeded",),
    }
    errors = []
    if result["status"] == "complete":
        errors.append("fault capture falsely reported complete")
    if mode in ("panic", "cancel", "delay") and result["status"] != "failed":
        errors.append("collector exception must produce failed snapshot")
    if not any(token in result["reason"].lower() for token in witnesses[mode]):
        errors.append("persisted snapshot does not identify the injected fault")
    return errors
