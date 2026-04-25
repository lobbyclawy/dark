#!/usr/bin/env python3

import unittest

from go_e2e_gate import decide


class GoE2EGateTests(unittest.TestCase):
    def test_push_always_runs(self) -> None:
        decision = decide("push", [], [])
        self.assertTrue(decision.run)
        self.assertIn("always runs", decision.reason)

    def test_confidential_label_runs(self) -> None:
        decision = decide("pull_request", ["confidential-vtxos"], [])
        self.assertTrue(decision.run)
        self.assertIn("confidential-vtxos", decision.reason)

    def test_risky_surface_runs_without_label(self) -> None:
        decision = decide("pull_request", [], ["crates/dark-core/src/application.rs"])
        self.assertTrue(decision.run)
        self.assertIn("parity-sensitive", decision.reason)

    def test_safe_pull_request_skips(self) -> None:
        decision = decide("pull_request", [], ["README.md", "docs/testing.md"])
        self.assertFalse(decision.run)
        self.assertIn("outside confidential", decision.reason)

    def test_non_pull_request_unknown_event_skips(self) -> None:
        decision = decide("issue_comment", [], [])
        self.assertFalse(decision.run)
        self.assertIn("unsupported event", decision.reason)


if __name__ == "__main__":
    unittest.main()
