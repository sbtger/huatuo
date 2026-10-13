# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Register expected artifacts before use; preserve registration history."""
import hashlib
import json
from pathlib import Path


class EvidenceStore:
    def __init__(self, output):
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.artifacts = {}
        self.journal = self.output / "registrations.jsonl"
        self.journal.touch()

    def relative(self, name):
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError(
                "evidence path must be relative inside the output: " + str(name)
            )
        if self.output not in (self.output / path).resolve().parents:
            raise ValueError("evidence resolves outside the output: " + str(name))
        return str(path)

    def register(self, name, role, target_id=None, format="text", minimum_documents=1):
        name = self.relative(name)
        artifact = dict(
            path=name,
            role=role,
            target_id=target_id,
            format=format,
            minimum_documents=minimum_documents,
        )
        if name in self.artifacts:
            if self.artifacts[name] != artifact:
                raise ValueError("conflicting artifact registration: " + name)
            return name
        self.artifacts[name] = artifact
        with self.journal.open("a") as stream:
            stream.write(json.dumps(artifact) + "\n")
        return name

    def expect_document(self, name):
        name = self.relative(name)
        if name not in self.artifacts:
            self.register(
                name, "feature_event", format="json_documents", minimum_documents=0
            )
        self.artifacts[name]["minimum_documents"] += 1

    def save(self, summary):
        artifacts = []
        for artifact in self.artifacts.values():
            item = dict(artifact)
            path = self.output / item["path"]
            if path.is_file():
                item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            artifacts.append(item)
        (self.output / "manifest.json").write_text(
            json.dumps(dict(schema_version=2, artifacts=artifacts), indent=2) + "\n"
        )
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
