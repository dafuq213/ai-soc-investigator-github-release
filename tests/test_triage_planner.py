import unittest

from src.case_models import CaseBuilder
from src.triage_planner import TriagePlanner


class Tools:
    def __init__(self): self.calls = []
    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            return {"ok": True, "data": [], "meta": {"count": 0}}
        return call


def process_case():
    return CaseBuilder.from_seed_result("CASE-PLAN", {"ok": True, "data": [{
        "alert_id": "seed", "timestamp": "2026-08-10T10:00:00Z", "host": "WS-001", "agent_id": "001", "rule": {"id": "1"},
        "event": {"data": {"win": {"eventdata": {"processGuid": "{proc}", "parentProcessGuid": "{parent}", "user": "analyst"}}}},
    }]})


class TriagePlannerTests(unittest.TestCase):
    def test_advertises_only_reference_resolvable_actions(self):
        card = TriagePlanner(Tools()).seed_card(process_case())
        self.assertEqual({item["id"] for item in card["available_actions"]}, {"ACT-PARENT", "ACT-CHILDREN", "ACT-PROCESS-NET", "ACT-SIBLINGS", "ACT-AUTH"})
        self.assertNotIn("{proc}", str(card))

    def test_resolves_parent_on_same_agent_without_model_arguments(self):
        tools, case = Tools(), process_case()
        planner = TriagePlanner(tools, hours=6)
        planner.run(case, lambda card, ledger: {"decision": "act", "action_id": "ACT-PARENT", "reason_code": "process_lineage"}, max_steps=1)
        self.assertEqual(tools.calls[0][0], "get_process_by_guid")
        self.assertEqual(tools.calls[0][1]["process_guid"], "{parent}")
        self.assertEqual(tools.calls[0][1]["agent_id"], "001")

    def test_rejects_action_not_advertised_by_seed(self):
        tools, case = Tools(), process_case()
        planner = TriagePlanner(tools)
        history = planner.run(case, lambda card, ledger: {"decision": "act", "action_id": "ACT-NOT-REAL", "reason_code": "process_lineage"})
        self.assertEqual(history[0]["status"], "rejected")
        self.assertFalse(tools.calls)


if __name__ == "__main__":
    unittest.main()
