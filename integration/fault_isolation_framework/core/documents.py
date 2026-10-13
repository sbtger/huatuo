# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import json


def read_documents(path):
    if not path.exists():
        return []
    raw = path.read_text()
    decoder = json.JSONDecoder()
    documents = []
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        try:
            document, offset = decoder.raw_decode(raw, offset)
        except json.JSONDecodeError:
            # The writer may be appending this record concurrently.
            break
        documents.append(document)
    return documents
