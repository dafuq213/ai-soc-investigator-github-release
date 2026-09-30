import unittest

from src.generic_assessment import generic_assessment_prompt, parse_generic_assessment


PACKET = {"alert": {"title": "Rule title"}, "evidence": [{"id": "E01", "summary": "Event 1; process cmd.exe"}, {"id": "E02", "summary": "Event 3; target 203.0.113.8"}]}


def _valid():
    return {
        "verdict": "suspicious_requires_review", "confidence": 65,
        "what_happened": [{"evidence_ids": ["E01"], "text": "The cited record shows a process execution on the monitored endpoint."}],
        "alert_claim_assessment": {"status": "partially_supported", "evidence_ids": ["E01"], "text": "The cited process execution supports that activity occurred, but not the full detection claim."},
        "hypotheses": [{"type": "possible_concern", "evidence_ids": ["E01", "E02"], "text": "The cited execution and network activity may warrant review because their relationship is observed in the packet."}],
        "unknowns": ["The packet does not establish the purpose or outcome of the activity."],
        "recommended_actions": [{"category": "investigate", "action": "Review the related process and network records around the cited activity.", "reason": "The cited execution and network observations require additional scoping before disposition.", "evidence_ids": ["E01", "E02"], "target": None, "priority": "high"}], "analyst_question": "Can the observed activity be tied to a known administrative task?",
    }


class GenericAssessmentTests(unittest.TestCase):
    def test_prompt_contains_only_packet_and_generic_contract(self):
        prompt = generic_assessment_prompt(PACKET)
        self.assertIn("Rule title", prompt)
        self.assertIn("exactly one JSON object", prompt)
        self.assertIn("one to 8 distinct supplied E## IDs", prompt)
        self.assertIn("not that it succeeded or returned particular data", prompt)
        self.assertIn("use `partially_supported` rather than `supported`", prompt)
        self.assertNotIn("Sysmon profile", prompt)

    def test_prompt_omits_provenance_and_duplicate_path_fields(self):
        packet = {"alert": {"title": "Rule"}, "collection": {}, "evidence": [{"id": "E01", "relationship": "seed_alert", "source": {"document_id": "private"}, "fields": {"host": "WS", "process_name": "cmd.exe", "process_path": "cmd.exe"}}]}
        prompt = generic_assessment_prompt(packet)
        self.assertNotIn("private", prompt)
        self.assertNotIn('"host":"WS"', prompt)

    def test_prompt_removes_retained_wazuh_transport_escaping(self):
        packet = {"alert": {"title": "Rule"}, "collection": {}, "evidence": [{"id": "E01", "relationship": "seed_alert", "fields": {"process_name": r"C:\\Windows\\System32\\cmd.exe", "command_line": '\\"cmd.exe\\" /c whoami &amp; hostname'}}]}
        prompt = generic_assessment_prompt(packet)
        self.assertIn("& hostname", prompt)
        self.assertNotIn("&amp;", prompt)
        self.assertNotIn(r"C:\\\\Windows", prompt)

    def test_normalizes_retained_domain_user_separator_for_target_validation(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{"id": "E01", "relationship": "seed_alert", "fields": {"user": "LAB-HOST\\\\analyst", "process_name": "cmd.exe"}}]}
        assessment = _valid()
        assessment["hypotheses"] = []
        assessment["recommended_actions"] = [{"category": "validate_context", "action": "Confirm whether the observed user context was expected for this alert.", "reason": "The user context is present but authorization is not established by the packet.", "evidence_ids": ["E01"], "target": "LAB-HOST\\analyst", "priority": "medium"}]
        self.assertEqual(parse_generic_assessment(assessment, packet)["assessment_status"], "accepted")

    def test_prompt_caps_repeated_model_evidence_but_retains_diverse_relationships(self):
        packet = {"alert": {"title": "Rule"}, "collection": {}, "evidence": [
            {"id": "E01", "relationship": "seed_alert", "fields": {}},
            *[{"id": f"E{index:02d}", "relationship": "same_process", "fields": {}} for index in range(2, 10)],
            {"id": "E10", "relationship": "same_domain", "fields": {}},
        ]}
        prompt = generic_assessment_prompt(packet)
        self.assertIn('"id":"E01"', prompt)
        self.assertIn('"id":"E10"', prompt)
        self.assertNotIn('"id":"E09"', prompt)
        self.assertIn("model received 8 of 10", prompt)

    def test_accepts_cited_generic_assessment(self):
        result = parse_generic_assessment(_valid(), PACKET)
        self.assertEqual(result["verdict"], "suspicious_requires_review")

    def test_rejects_completed_operation_claim_supported_only_by_command_intent(self):
        packet = {"alert": {"title": "Registry alert"}, "evidence": [{
            "id": "E01", "relationship": "seed_alert",
            "fields": {"process_name": "reg.exe", "command_line": "reg add HKCU\\Software\\Example /v Name /d value"},
        }]}
        assessment = _valid()
        assessment["what_happened"] = [{"evidence_ids": ["E01"], "text": "The actual value written is a plaintext command in the registry."}]
        assessment["alert_claim_assessment"] = {"status": "partially_supported", "evidence_ids": ["E01"], "text": "The registry command is observed, but its successful outcome is not established."}
        assessment["hypotheses"] = []
        with self.assertRaisesRegex(ValueError, "command-line intent without cited outcome telemetry"):
            parse_generic_assessment(assessment, packet)

    def test_accepts_completed_operation_claim_with_cited_outcome_telemetry(self):
        packet = {"alert": {"title": "Registry alert"}, "evidence": [{
            "id": "E01", "relationship": "seed_alert",
            "fields": {"registry_key": "HKCU\\Software\\Example", "registry_value": "value"},
        }]}
        assessment = _valid()
        assessment["what_happened"] = [{"evidence_ids": ["E01"], "text": "The registry value was added to the observed key."}]
        assessment["alert_claim_assessment"] = {"status": "supported", "evidence_ids": ["E01"], "text": "The cited registry event supports the recorded value addition."}
        assessment["hypotheses"] = []
        assessment["recommended_actions"] = [{"category": "investigate", "action": "Review subsequent activity associated with the observed registry value.", "reason": "The cited registry event warrants scoping for related process activity.", "evidence_ids": ["E01"], "target": None, "priority": "medium"}]
        self.assertEqual(parse_generic_assessment(assessment, packet)["assessment_status"], "accepted")

    def test_rejects_unknown_evidence_and_ignores_extra_keys(self):
        bad = _valid()
        bad["what_happened"][0]["evidence_ids"] = ["E99"]
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            parse_generic_assessment(bad, PACKET)
        bad = _valid()
        bad["unexpected"] = True
        result = parse_generic_assessment(bad, PACKET)
        self.assertTrue(any(flag["code"] == "extra_fields_removed" for flag in result["quality_flags"]))

    def test_distinguishes_excessive_duplicate_and_unknown_citations(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{"id": f"E{index:02d}"} for index in range(1, 10)]}
        bad = _valid()
        bad["what_happened"][0]["evidence_ids"] = [f"E{index:02d}" for index in range(1, 10)]
        with self.assertRaisesRegex(ValueError, "maximum of 8"):
            parse_generic_assessment(bad, packet)
        bad["what_happened"][0]["evidence_ids"] = ["E01", "E01"]
        self.assertEqual(parse_generic_assessment(bad, packet)["what_happened"][0]["evidence_ids"], ["E01"])
        bad["what_happened"][0]["evidence_ids"] = ["E99"]
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            parse_generic_assessment(bad, packet)

    def test_downgrades_unjustified_malicious_and_removes_containment(self):
        packet = {**PACKET, "observed_entities": {"host": "WS-01"}}
        bad = _valid()
        bad["verdict"] = "likely_malicious"
        bad["confidence"] = 80
        bad["hypotheses"] = [{"type": "possible_concern", "evidence_ids": ["E01"], "text": "The cited activity may warrant review before a final conclusion can be made."}]
        bad["recommended_actions"] = [{"category": "consider_response", "action": "Isolate the observed host after human approval.", "reason": "Human approval is required because isolation may interrupt business operations.", "evidence_ids": ["E01"], "target": "WS-01", "priority": "high"}]
        result = parse_generic_assessment(bad, packet)
        self.assertEqual(result["verdict"], "suspicious_requires_review")
        self.assertEqual(result["recommended_actions"], [])

    def test_rejects_containment_without_an_observed_host_target(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{"id": "E01", "relationship": "seed_alert"}, {"id": "E02", "relationship": "same_ip"}]}
        assessment = _valid()
        assessment["verdict"] = "likely_malicious"
        assessment["confidence"] = 70
        assessment["hypotheses"] = [
            {"type": "possible_concern", "evidence_ids": ["E01", "E02"], "text": "The cited execution and related event may warrant review because both were observed."},
        ]
        assessment["recommended_actions"] = [{"category": "consider_response", "action": "Isolate WS-01 after human approval.", "reason": "Human approval is required because isolation may interrupt business operations.", "evidence_ids": ["E01", "E02"], "target": "WS-01", "priority": "high"}]
        result = parse_generic_assessment(assessment, packet)
        self.assertEqual(result["recommended_actions"], [])

    def test_rejects_more_than_two_narrative_items_to_protect_token_budget(self):
        bad = _valid()
        bad["what_happened"].append(dict(bad["what_happened"][0]))
        bad["what_happened"].append(dict(bad["what_happened"][0]))
        result = parse_generic_assessment(bad, PACKET)
        self.assertEqual(len(result["what_happened"]), 2)
        self.assertTrue(any(flag["code"] == "what_happened_truncated" for flag in result["quality_flags"]))

    def test_rejects_low_confidence_benign_and_hypothesis_in_observed_section(self):
        bad = _valid()
        bad["verdict"] = "likely_benign"
        bad["confidence"] = 0
        bad["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01", "E02"], "text": "The observed sequence is consistent with a bounded endpoint workflow, but does not establish authorization."}]
        self.assertEqual(parse_generic_assessment(bad, PACKET)["verdict"], "inconclusive")
        bad["verdict"] = "inconclusive"
        bad["confidence"] = 50
        bad["what_happened"] = [{"evidence_ids": ["E01"], "text": "The observed event is consistent with an authorized process execution."}]
        with self.assertRaisesRegex(ValueError, "what_happened must contain observations"):
            parse_generic_assessment(bad, PACKET)

    def test_rejects_benign_verdict_without_a_stated_evidence_limit(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{"id": "E01", "relationship": "seed_alert"}, {"id": "E02", "relationship": "parent_process_origin"}]}
        assessment = _valid()
        assessment["verdict"] = "likely_benign"
        assessment["confidence"] = 50
        assessment["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01", "E02"], "text": "The observed sequence is consistent with a bounded endpoint workflow under review."}]
        assessment["unknowns"] = []
        self.assertEqual(parse_generic_assessment(assessment, packet)["verdict"], "inconclusive")

    def test_flags_external_context_terms_in_bounded_hypothesis(self):
        bad = _valid()
        bad["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "This is consistent with a known compliance pattern for the observed endpoint process."}]
        result = parse_generic_assessment(bad, PACKET)
        self.assertEqual(result["assessment_status"], "accepted_with_flags")
        self.assertEqual(result["quality_flags"][0]["code"], "unverified_operational_context")

    def test_accepts_four_distinct_unknowns_but_not_five(self):
        assessment = _valid()
        assessment["unknowns"] = [
            "The packet does not establish the initiating user intent for this activity.",
            "The packet does not show whether a remote service accepted a connection.",
            "The packet does not include signer or file provenance information.",
            "The packet does not show whether a later process changed the endpoint.",
        ]
        self.assertEqual(parse_generic_assessment(assessment, PACKET)["verdict"], "suspicious_requires_review")
        assessment["unknowns"].append("The packet lacks one additional unrelated observation.")
        result = parse_generic_assessment(assessment, PACKET)
        self.assertEqual(len(result["unknowns"]), 4)
        self.assertTrue(any(flag["code"] == "unknowns_truncated" for flag in result["quality_flags"]))

    def test_flags_software_provenance_language_from_path_names(self):
        bad = _valid()
        bad["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "The observed sequence is consistent with a user-installed bundled application."}]
        result = parse_generic_assessment(bad, PACKET)
        self.assertEqual(result["assessment_status"], "accepted_with_flags")
        self.assertIn("user-installed", result["quality_flags"][0]["message"])

    def test_unbounded_optional_hypothesis_is_quarantined_and_unique_type_is_required(self):
        bad = _valid()
        bad["hypotheses"] = [{"type": "possible_concern", "evidence_ids": ["E01"], "text": "The cited process executed on the endpoint and requires investigation."}]
        result = parse_generic_assessment(bad, PACKET)
        self.assertEqual(result["assessment_status"], "accepted_with_flags")
        self.assertEqual(result["hypotheses"], [])
        self.assertEqual(result["quality_flags"][0]["code"], "hypothesis_removed_unbounded")
        self.assertEqual(result["section_validation"]["hypotheses"], "accepted_with_flags")
        self.assertEqual(result["section_validation"]["what_happened"], "accepted")
        bad["hypotheses"] = [
            {"type": "possible_concern", "evidence_ids": ["E01"], "text": "The observed sequence may warrant review because a process was recorded."},
            {"type": "possible_concern", "evidence_ids": ["E02"], "text": "The observed sequence could indicate related network activity."},
        ]
        result = parse_generic_assessment(bad, PACKET)
        self.assertEqual(len(result["hypotheses"]), 1)
        self.assertTrue(any(flag["code"] == "hypothesis_removed_duplicate_type" for flag in result["quality_flags"]))

    def test_accepts_equivalent_bounded_hypothesis_language(self):
        variants = [
            "Automated administration may legitimately produce the observed process chain.",
            "The activity might reflect an administrative workflow.",
            "The activity could reflect an administrative workflow.",
            "The activity possibly reflects an administrative workflow.",
            "The activity potentially reflects an administrative workflow.",
            "One possible explanation is an administrative workflow.",
            "The available evidence cannot determine whether this was administrative activity.",
        ]
        for text in variants:
            with self.subTest(text=text):
                assessment = _valid()
                assessment["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": text}]
                result = parse_generic_assessment(assessment, PACKET)
                self.assertEqual(len(result["hypotheses"]), 1)

    def test_quarantined_hypothesis_cannot_support_a_high_impact_verdict(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [
            {"id": "E01", "relationship": "seed_alert"},
            {"id": "E02", "relationship": "same_process"},
        ]}
        assessment = _valid()
        assessment["verdict"] = "likely_malicious"
        assessment["confidence"] = 80
        assessment["hypotheses"] = [{
            "type": "possible_concern",
            "evidence_ids": ["E01", "E02"],
            "text": "This activity is malicious and requires containment.",
        }]
        result = parse_generic_assessment(assessment, packet)
        self.assertEqual(result["verdict"], "suspicious_requires_review")

    def test_accepts_captured_claude_hypotheses_from_case_b18ba2(self):
        assessment = _valid()
        assessment["confidence"] = 60
        assessment["hypotheses"] = [
            {
                "type": "possible_concern",
                "evidence_ids": ["E02"],
                "text": "systeminfo combined with registry disk enumeration via PowerShell-spawned cmd could indicate reconnaissance activity and may warrant review",
            },
            {
                "type": "possible_legitimate_context",
                "evidence_ids": ["E01", "E02"],
                "text": "Automated admin scripts or monitoring tools may legitimately chain PowerShell, cmd, and system queries in this pattern",
            },
        ]
        result = parse_generic_assessment(assessment, PACKET)
        self.assertEqual(result["assessment_status"], "accepted_with_flags")
        self.assertEqual(len(result["hypotheses"]), 2)
        self.assertTrue(any(flag["code"] == "unverified_operational_context" for flag in result["quality_flags"]))

    def test_alert_claim_can_reference_detection_term_and_hypothesis_can_be_flagged(self):
        allowed = _valid()
        allowed["alert_claim_assessment"]["text"] = "The cited process record does not confirm injection because no additional supporting evidence is present."
        self.assertEqual(parse_generic_assessment(allowed, PACKET)["alert_claim_assessment"]["status"], "partially_supported")
        bad = _valid()
        bad["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "The observed sequence is consistent with a controlled test workflow on the endpoint."}]
        self.assertEqual(parse_generic_assessment(bad, PACKET)["assessment_status"], "accepted_with_flags")

    def test_unverified_context_flag_does_not_reject_suspicious_verdict(self):
        bad = _valid()
        bad["confidence"] = 72
        bad["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "The observed sequence is consistent with expected maintenance activity."}]
        result = parse_generic_assessment(bad, PACKET)
        self.assertEqual(result["assessment_status"], "accepted_with_flags")

    def test_unverified_context_still_caps_likely_benign_confidence(self):
        packet = {"alert": {"title": "Rule"}, "observed_entities": {"host": "WS-01"}, "evidence": [
            {"id": "E01", "relationship": "seed_alert"},
            {"id": "E02", "relationship": "parent_process_origin"},
        ]}
        bad = _valid()
        bad["verdict"] = "likely_benign"
        bad["confidence"] = 70
        bad["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01", "E02"], "text": "The observed sequence is consistent with expected maintenance activity."}]
        result = parse_generic_assessment(bad, packet)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["confidence"], 65)

    def test_captured_five_citation_response_is_structurally_accepted(self):
        packet = {"alert": {"title": "Windows command prompt started by an abnormal process"}, "evidence": [
            {"id": f"E{index:02d}", "relationship": "seed_alert" if index == 1 else "direct_child_process"}
            for index in range(1, 7)
        ]}
        response = {
            "verdict": "suspicious_requires_review",
            "confidence": 72,
            "what_happened": [{"evidence_ids": ["E01", "E05", "E03", "E02", "E04"], "text": "PowerShell spawned cmd.exe, which requested local user, group, directory, and credential-entry listings."}],
            "alert_claim_assessment": {"status": "partially_supported", "evidence_ids": ["E01"], "text": "The parent process is observed, but the packet does not independently establish that it is abnormal."},
            "hypotheses": [
                {"type": "possible_concern", "evidence_ids": ["E01", "E04", "E05", "E03", "E02"], "text": "The chained discovery operations could indicate post-access discovery activity."},
                {"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "An automated administrative script is consistent with the command chain and requires authorization review."},
            ],
            "unknowns": ["The packet does not establish authorization or whether each requested operation succeeded."],
            "recommended_actions": [{"category": "investigate", "action": "Review subsequent process activity from the observed command chain.", "reason": "The cited chained discovery commands may warrant scoping for follow-on activity.", "evidence_ids": ["E01", "E04"], "target": None, "priority": "high"}],
            "analyst_question": "Can the owning team confirm whether this PowerShell-launched discovery sequence was authorized?",
        }
        result = parse_generic_assessment(response, packet)
        self.assertEqual(result["assessment_status"], "accepted_with_flags")
        self.assertEqual(result["verdict"], "suspicious_requires_review")

    def test_flags_weak_same_hash_correlation_and_unverified_software_ownership(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{"id": "E01", "relationship": "same_hash"}, {"id": "E02", "relationship": "same_hash"}]}
        assessment = _valid()
        assessment["hypotheses"] = [{"type": "possible_concern", "evidence_ids": ["E01", "E02"], "text": "The observed sequence may warrant review because the same hash appears in both records."}]
        flags = parse_generic_assessment(assessment, packet)["quality_flags"]
        self.assertEqual(flags[0]["code"], "weak_correlation_basis")
        assessment["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "The observed sequence is consistent with software using its own registry key."}]
        flags = parse_generic_assessment(assessment, packet)["quality_flags"]
        self.assertTrue(any(item["code"] == "unverified_software_identity" for item in flags))

    def test_flags_unverified_maintenance_and_widely_separated_evidence(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [
            {"id": "E01", "relationship": "seed_alert", "timestamp_utc": "2026-09-05T10:00:00Z"},
            {"id": "E02", "relationship": "parent_process_origin", "timestamp_utc": "2026-09-05T10:30:01Z"},
        ]}
        assessment = _valid()
        assessment["hypotheses"] = [{"type": "possible_legitimate_context", "evidence_ids": ["E01", "E02"], "text": "The observed sequence is consistent with a scheduled maintenance task."}]
        flags = parse_generic_assessment(assessment, packet)["quality_flags"]
        self.assertTrue(any(item["code"] == "unverified_operational_context" for item in flags))
        self.assertTrue(any(item["code"] == "weak_temporal_link" for item in flags))
        self.assertEqual(sum(item["code"] == "weak_temporal_link" for item in flags), 1)

    def test_accepts_independently_written_grounded_recommendation(self):
        packet = {"alert": {"title": "Rule"}, "observed_entities": {"host": "WS-01"}, "evidence": [{"id": "E01", "relationship": "seed_alert", "fields": {"host": "WS-01", "process_name": "cmd.exe"}}]}
        assessment = _valid()
        assessment["hypotheses"] = []
        assessment["recommended_actions"] = [{"category": "investigate", "action": "Review subsequent child-process activity on WS-01 around the alert time.", "reason": "The cited command execution requires scoping before the alert can be dispositioned.", "evidence_ids": ["E01"], "target": "WS-01", "priority": "high"}]
        result = parse_generic_assessment(assessment, packet)
        self.assertEqual(result["recommended_actions"][0]["action"], assessment["recommended_actions"][0]["action"])

    def test_accepts_concrete_file_target_embedded_in_observed_command_line(self):
        path = r"C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1"
        packet = {"alert": {"title": "Rule"}, "evidence": [{
            "id": "E01", "relationship": "seed_alert",
            "fields": {"command_line": f"powershell -noexit -file {path}"},
        }]}
        assessment = _valid()
        assessment["hypotheses"] = []
        assessment["recommended_actions"] = [{
            "category": "investigate", "action": "Retrieve and inspect the observed script path.",
            "reason": "The cited command line invokes the script but its contents are not in evidence.",
            "evidence_ids": ["E01"], "target": path, "priority": "high",
        }]
        result = parse_generic_assessment(assessment, packet)
        self.assertEqual(result["recommended_actions"][0]["target"], path)

    def test_rejects_arbitrary_substring_as_recommendation_target(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{
            "id": "E01", "relationship": "seed_alert",
            "fields": {"command_line": r"powershell -file C:\Observed\script.ps1"},
        }]}
        assessment = _valid()
        assessment["hypotheses"] = []
        assessment["recommended_actions"] = [{
            "category": "investigate", "action": "Review the observed command context.",
            "reason": "The cited command requires additional investigation.",
            "evidence_ids": ["E01"], "target": "Observed", "priority": "medium",
        }]
        self.assertEqual(parse_generic_assessment(assessment, packet)["recommended_actions"], [])

    def test_rejects_invented_target_and_disguised_response_action(self):
        assessment = _valid()
        assessment["recommended_actions"][0]["target"] = "UNKNOWN-HOST"
        self.assertEqual(parse_generic_assessment(assessment, PACKET)["recommended_actions"], [])
        assessment = _valid()
        assessment["recommended_actions"][0]["action"] = "Isolate the endpoint while the investigation continues."
        self.assertEqual(parse_generic_assessment(assessment, PACKET)["recommended_actions"], [])

    def test_rejects_concrete_identifier_absent_from_evidence(self):
        assessment = _valid()
        assessment["recommended_actions"][0]["action"] = "Review child activity from invented.exe around the alert time."
        self.assertEqual(parse_generic_assessment(assessment, PACKET)["recommended_actions"], [])

    def test_allows_investigation_of_an_observed_destructive_command_name(self):
        packet = {"alert": {"title": "Rule"}, "evidence": [{"id": "E01", "relationship": "seed_alert", "fields": {"process_name": "powershell.exe", "command_line": "Remove-Item C:\\Temp\\x.txt"}}]}
        assessment = _valid()
        assessment["hypotheses"] = []
        assessment["recommended_actions"] = [{"category": "investigate", "action": "Review whether the observed Remove-Item command produced a file-deletion event.", "reason": "The command line records a deletion request but does not establish its outcome.", "evidence_ids": ["E01"], "target": None, "priority": "high"}]
        assessment["what_happened"] = [{"evidence_ids": ["E01"], "text": "PowerShell was invoked with a command requesting removal of a file."}]
        assessment["alert_claim_assessment"] = {"status": "partially_supported", "evidence_ids": ["E01"], "text": "The command is observed, but successful file removal is not established."}
        self.assertEqual(parse_generic_assessment(assessment, packet)["assessment_status"], "accepted")

    def test_response_recommendation_requires_strong_verdict_and_explicit_approval(self):
        assessment = _valid()
        assessment["recommended_actions"] = [{"category": "consider_response", "action": "Consider isolating the endpoint.", "reason": "The cited behavior may require containment after review.", "evidence_ids": ["E01", "E02"], "target": None, "priority": "high"}]
        self.assertEqual(parse_generic_assessment(assessment, PACKET)["recommended_actions"], [])
        assessment["verdict"] = "likely_malicious"
        assessment["confidence"] = 75
        self.assertEqual(parse_generic_assessment(assessment, PACKET)["recommended_actions"], [])

    def test_normalizes_integer_like_confidence_and_quarantines_one_bad_recommendation(self):
        assessment = _valid()
        assessment["confidence"] = "72"
        assessment["recommended_actions"].append({
            "category": "investigate", "action": "Review invented.exe activity.",
            "reason": "This identifier is absent from the evidence packet.",
            "evidence_ids": ["E01"], "target": None, "priority": "medium",
        })
        result = parse_generic_assessment(assessment, PACKET)
        self.assertEqual(result["confidence"], 72)
        self.assertEqual(len(result["recommended_actions"]), 1)
        self.assertTrue(any(flag["code"] == "recommendation_removed_invalid" for flag in result["quality_flags"]))


if __name__ == "__main__":
    unittest.main()
