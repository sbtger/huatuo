# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import unittest
from log_policy import unexpected_logs


class LogPolicyTest(unittest.TestCase):
    def test_warning_cannot_hide_behind_fault_marker(self):
        log = 'MEMSNAP_FAULT id=go/panic action=panic pid=42 stage=provider\nlevel="warn" msg="unrelated broken watcher"\n'
        self.assertEqual(len(unexpected_logs(log)), 1)

    def test_expected_recovered_runtime_panic(self):
        log = 'MEMSNAP_FAULT id=go/panic action=panic pid=42 stage=provider\nlevel="error" msg="runtime snapshot panicked" panic="test-only runtime snapshot panic" pid="42"\n'
        self.assertEqual(unexpected_logs(log), [])

    def test_panic_without_matching_target_is_rejected(self):
        log = 'MEMSNAP_FAULT id=go/panic action=panic pid=42 stage=provider\nlevel="error" msg="runtime snapshot panicked" panic="test-only runtime snapshot panic" pid="43"\n'
        self.assertEqual(len(unexpected_logs(log)), 1)

    def test_uncontrolled_panic_is_rejected(self):
        self.assertEqual(len(unexpected_logs("panic: unexpected nil pointer\n")), 1)


if __name__ == "__main__":
    unittest.main()
