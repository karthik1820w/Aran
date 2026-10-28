import unittest
from datetime import date

from helpers import KB_PATH, load_kb, mutated, raw_kb
from brandguardian.knowledge import KnowledgeBase, KnowledgeError


class KnowledgeLoadTests(unittest.TestCase):
    def test_demo_knowledge_loads(self):
        kb = load_kb()
        self.assertEqual(kb.version_label, "Nova Foods Brand Guidelines v3.2")
        self.assertIn("BG-4.1", kb.rules)
        self.assertEqual(len(kb.ledger), 4)

    def test_from_file_matches_from_dict(self):
        self.assertEqual(KnowledgeBase.from_file(KB_PATH).fingerprint, load_kb().fingerprint)

    def test_fingerprint_changes_when_content_changes(self):
        changed = KnowledgeBase.from_dict(mutated(lambda d: d["rules"][0].update(text="Different wording.")))
        self.assertNotEqual(changed.fingerprint, load_kb().fingerprint)

    def test_source_label_cites_version_and_clause(self):
        self.assertEqual(load_kb().source_label("BG-4.1"), "Nova Foods Brand Guidelines v3.2, section 4.1")

    def test_public_summary_hides_patterns(self):
        summary = load_kb().public_summary()
        self.assertNotIn("matches", str(summary))
        self.assertEqual(len(summary["rules"]), 13)

    def test_ledger_validity_boundaries_are_inclusive(self):
        entry = load_kb().ledger["C-201"]
        self.assertTrue(entry.is_valid_on(date(2025, 12, 31)))
        self.assertFalse(entry.is_valid_on(date(2026, 1, 1)))
        self.assertTrue(entry.is_valid_on(date(2024, 6, 1)))
        self.assertFalse(entry.is_valid_on(date(2024, 5, 31)))

    def test_ledger_for_topic_returns_only_valid_entries(self):
        kb = load_kb()
        self.assertEqual([e.id for e in kb.ledger_for_topic("protein", date(2026, 10, 26))], ["C-102"])
        self.assertEqual(kb.ledger_for_topic("rankings", date(2026, 10, 26)), [])


class KnowledgeValidationTests(unittest.TestCase):
    def assertProblem(self, data, fragment):
        with self.assertRaises(KnowledgeError) as ctx:
            KnowledgeBase.from_dict(data)
        self.assertTrue(any(fragment in p for p in ctx.exception.problems), ctx.exception.problems)

    def test_missing_brand(self):
        self.assertProblem(mutated(lambda d: d.pop("brand")), "missing 'brand'")

    def test_no_rules(self):
        self.assertProblem(mutated(lambda d: d.update(rules=[])), "at least one rule")

    def test_duplicate_rule_id(self):
        self.assertProblem(mutated(lambda d: d["rules"].append(dict(d["rules"][0]))), "duplicate rule id")

    def test_invalid_severity(self):
        self.assertProblem(mutated(lambda d: d["rules"][0].update(severity="critical")), "severity")

    def test_invalid_regex(self):
        self.assertProblem(mutated(lambda d: d["claim_rules"][0].update(patterns=["(unclosed"])), "invalid regex")

    def test_catastrophic_regex_rejected(self):
        self.assertProblem(mutated(lambda d: d["claim_rules"][0].update(patterns=["(a+)+$"])), "catastrophic")

    def test_overlong_regex_rejected(self):
        self.assertProblem(mutated(lambda d: d["claim_rules"][0].update(patterns=["a" * 300])), "longer than")

    def test_unknown_rule_reference(self):
        self.assertProblem(mutated(lambda d: d["glossary"][0].update(rule_id="BG-99")), "unknown rule_id")

    def test_bad_date(self):
        self.assertProblem(mutated(lambda d: d["ledger"][0].update(valid_until="31/12/2026")), "invalid ISO date")

    def test_valid_from_after_valid_until(self):
        self.assertProblem(mutated(lambda d: d["ledger"][0].update(valid_from="2030-01-01")), "after valid_until")

    def test_extract_needs_named_group(self):
        self.assertProblem(mutated(lambda d: d["ledger"][0].update(extract=r"(\d+) g")), "named group")

    def test_extract_needs_expected(self):
        self.assertProblem(mutated(lambda d: d["ledger"][0].pop("expected")), "'expected' is required")

    def test_extract_needs_rule_id(self):
        self.assertProblem(mutated(lambda d: d["ledger"][0].pop("rule_id")), "'rule_id' is required")

    def test_duplicate_ledger_id(self):
        self.assertProblem(mutated(lambda d: d["ledger"].append(dict(d["ledger"][0]))), "duplicate ledger id")

    def test_glossary_needs_avoid_terms(self):
        self.assertProblem(mutated(lambda d: d["glossary"][0].update(avoid=[])), "at least one term")

    def test_all_problems_are_reported_together(self):
        def break_many(d):
            d.pop("brand")
            d["rules"][0]["severity"] = "nope"
            d["ledger"][0]["valid_until"] = "bad"
        with self.assertRaises(KnowledgeError) as ctx:
            KnowledgeBase.from_dict(mutated(break_many))
        self.assertGreaterEqual(len(ctx.exception.problems), 3)

    def test_raw_demo_file_is_valid_json_with_sample(self):
        self.assertIn("NovaBar", raw_kb()["sample_post"])


if __name__ == "__main__":
    unittest.main()
