import unittest
from contract import validate_phase


class ContractTest(unittest.TestCase):
    def good(self):
        return dict(
            samples=30,
            errors=[],
            identity_before=[42, 123],
            identity_after=[42, 123],
            tick_before=10,
            tick_after=20,
            seq_before=3,
            seq_after=8,
            total=468,
            fault_expected=True,
            fault_hits=1,
            scheduled=30,
            completed=30,
            largest_success_gap=0.2,
            max_gap=2.0,
        )

    def test_valid_phase(self):
        self.assertEqual(validate_phase(self.good()), [])

    def test_rejects_business_restart(self):
        p = self.good()
        p["identity_after"] = [43, 124]
        self.assertIn("process identity changed", validate_phase(p))

    def test_rejects_stalled_background_task(self):
        p = self.good()
        p["tick_after"] = 10
        self.assertIn("background task stalled", validate_phase(p))

    def test_rejects_acknowledged_state_corruption(self):
        p = self.good()
        p["total"] = 467
        self.assertIn("business state mismatch", validate_phase(p))

    def test_rejects_unreached_fault(self):
        p = self.good()
        p["fault_hits"] = 0
        self.assertIn("fault was not reached", validate_phase(p))

    def test_rejects_unserved_scheduled_requests(self):
        p = self.good()
        p["completed"] = 29
        self.assertIn("scheduled requests were lost", validate_phase(p))

    def test_rejects_empty_phase(self):
        p = self.good()
        p["samples"] = 0
        self.assertIn("empty observation phase", validate_phase(p))

    def test_rejects_wrong_http_body(self):
        p = self.good()
        p["errors"] = ["wrong body"]
        self.assertIn("business request errors", validate_phase(p))

    def test_rejects_service_gap(self):
        p = self.good()
        p["largest_success_gap"] = 3
        self.assertIn("service progress gap exceeded bound", validate_phase(p))

    def test_rejects_stalled_transactions(self):
        p = self.good()
        p["seq_after"] = 3
        self.assertIn("transactions stalled", validate_phase(p))


class FaultContractTest(unittest.TestCase):
    def test_unrelated_partial_cannot_prove_efault(self):
        from contract import validate_fault

        self.assertTrue(
            validate_fault(
                "efault", {"status": "partial", "reason": "heap changed concurrently"}
            )
        )

    def test_unrelated_failure_cannot_prove_timeout(self):
        from contract import validate_fault

        self.assertTrue(
            validate_fault(
                "delay", {"status": "failed", "reason": "unsupported architecture"}
            )
        )

    def test_failed_bad_address_proves_efault(self):
        from contract import validate_fault

        self.assertEqual(
            validate_fault(
                "efault",
                {"status": "failed", "reason": "read runtime metadata: bad address"},
            ),
            [],
        )


class RuntimeShortReadTest(unittest.TestCase):
    def test_hotspot_short_read_witness(self):
        from contract import validate_fault

        self.assertEqual(
            validate_fault(
                "short",
                {
                    "status": "failed",
                    "reason": "external HotSpot heap scan failed: short HotSpot memory read: got 7, want 8",
                },
            ),
            [],
        )

    def test_cpython_short_read_witness(self):
        from contract import validate_fault

        self.assertEqual(
            validate_fault(
                "short",
                {
                    "status": "failed",
                    "reason": "short CPython process memory read: got 7, want 8",
                },
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
