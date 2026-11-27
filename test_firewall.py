"""
The same test cases are also shown in the dashboard ("Test Cases" page)
through run_test_cases(), with expected vs actual results and PASS/FAIL.

Rule tuple format: (priority, action, source, port, protocol)
Packet tuple format: (src_ip, dst_ip, dst_port, protocol)
"""

import unittest

from firewall import (
    EXAMPLE_RULES,
    FirewallEngine,
    ValidationError,
    generate_sample_packets,
    make_packet,
    security_observations,
    validate_ip,
    validate_port,
    validate_priority,
    validate_protocol,
    validate_source,
)

SERVER = "10.0.0.10"

# Each case: id, category, description, default policy, rules (in the order
# they are ADDED), packet, expected action, expected priority of the matching
# rule (None = no rule should match, so the default policy decides).
TEST_CASES = [
    ("T01", "Allowed packet", "Subnet host reaches web server (rule 20)",
     "DENY", EXAMPLE_RULES, ("192.168.1.50", SERVER, 80, "TCP"), "ALLOW", 20),
    ("T02", "Denied packet", "Blocked host tries Telnet (rule 10)",
     "DENY", EXAMPLE_RULES, ("192.168.1.10", SERVER, 23, "TCP"), "DENY", 10),
    ("T03", "Unknown source IP", "Unknown outside host uses HTTPS (ANY source rule 30)",
     "DENY", EXAMPLE_RULES, ("203.0.113.9", SERVER, 443, "TCP"), "ALLOW", 30),
    ("T04", "Unknown source IP", "Unknown outside host tries SSH (rule 40)",
     "DENY", EXAMPLE_RULES, ("203.0.113.9", SERVER, 22, "TCP"), "DENY", 40),
    ("T05", "Unknown source IP", "Unknown host on port 80: subnet-only rule 20 does not match",
     "DENY", EXAMPLE_RULES, ("203.0.113.9", SERVER, 80, "TCP"), "DENY", None),
    ("T06", "Different protocols", "UDP on port 80: rule 20 needs TCP, so no match",
     "DENY", EXAMPLE_RULES, ("192.168.1.50", SERVER, 80, "UDP"), "DENY", None),
    ("T07", "Different protocols", "Rule with protocol ANY blocks UDP Telnet too (rule 10)",
     "DENY", EXAMPLE_RULES, ("192.168.1.10", SERVER, 23, "UDP"), "DENY", 10),
    ("T08", "Different protocols", "ICMP ping allowed by an ICMP rule",
     "DENY", [(10, "ALLOW", "ANY", "ANY", "ICMP")], ("10.0.0.5", SERVER, None, "ICMP"), "ALLOW", 10),
    ("T09", "Different protocols", "TCP packet does not match the ICMP-only rule",
     "DENY", [(10, "ALLOW", "ANY", "ANY", "ICMP")], ("10.0.0.5", SERVER, 80, "TCP"), "DENY", None),
    ("T10", "Rule ordering", "DENY (priority 10) is checked before ALLOW (priority 20)",
     "DENY", [(10, "DENY", "ANY", "22", "ANY"), (20, "ALLOW", "ANY", "22", "ANY")],
     ("203.0.113.9", SERVER, 22, "TCP"), "DENY", 10),
    ("T11", "Rule ordering", "Priorities swapped: ALLOW now runs first, so ALLOW wins",
     "DENY", [(10, "ALLOW", "ANY", "22", "ANY"), (20, "DENY", "ANY", "22", "ANY")],
     ("203.0.113.9", SERVER, 22, "TCP"), "ALLOW", 10),
    ("T12", "Rule ordering", "Rule added first but with priority 50 runs AFTER priority 5",
     "ALLOW", [(50, "ALLOW", "ANY", "22", "ANY"), (5, "DENY", "ANY", "22", "ANY")],
     ("203.0.113.9", SERVER, 22, "TCP"), "DENY", 5),
    ("T13", "Rule ordering", "Equal priority: the rule created first wins",
     "DENY", [(10, "ALLOW", "ANY", "80", "TCP"), (10, "DENY", "ANY", "80", "TCP")],
     ("203.0.113.9", SERVER, 80, "TCP"), "ALLOW", 10),
    ("T14", "Overlapping rules", "Specific DENY for one host beats the subnet ALLOW",
     "DENY", [(10, "DENY", "192.168.1.10", "ANY", "ANY"), (20, "ALLOW", "192.168.1.0/24", "80", "TCP")],
     ("192.168.1.10", SERVER, 80, "TCP"), "DENY", 10),
    ("T15", "Overlapping rules", "Another host in the same subnet is allowed by rule 20",
     "DENY", [(10, "DENY", "192.168.1.10", "ANY", "ANY"), (20, "ALLOW", "192.168.1.0/24", "80", "TCP")],
     ("192.168.1.20", SERVER, 80, "TCP"), "ALLOW", 20),
    ("T16", "Overlapping rules", "Broad ALLOW placed first shadows the specific DENY",
     "DENY", [(10, "ALLOW", "192.168.1.0/24", "80", "TCP"), (20, "DENY", "192.168.1.10", "ANY", "ANY")],
     ("192.168.1.10", SERVER, 80, "TCP"), "ALLOW", 10),
    ("T17", "No matching rule", "Port 8080 matches nothing; default DENY applies",
     "DENY", EXAMPLE_RULES, ("203.0.113.9", SERVER, 8080, "TCP"), "DENY", None),
    ("T18", "Default ALLOW", "Port 8080 matches nothing; default ALLOW applies",
     "ALLOW", EXAMPLE_RULES, ("203.0.113.9", SERVER, 8080, "TCP"), "ALLOW", None),
    ("T19", "Default ALLOW", "Default ALLOW does not override an explicit DENY rule",
     "ALLOW", EXAMPLE_RULES, ("203.0.113.9", SERVER, 22, "TCP"), "DENY", 40),
    ("T20", "Default DENY", "Empty rule list with default DENY blocks everything",
     "DENY", [], ("192.168.1.50", SERVER, 80, "TCP"), "DENY", None),
]


def build_engine(default_policy, rules):
    engine = FirewallEngine(default_policy)
    for priority, action, source, port, protocol in rules:
        engine.add_rule(action, source, port, protocol, priority)
    return engine


def run_test_cases():
    """Run every case on a fresh engine. Returns a list of result dicts."""
    results = []
    for case_id, category, desc, default, rules, packet_t, exp_action, exp_prio in TEST_CASES:
        engine = build_engine(default, rules)
        packet = make_packet(*packet_t)
        decision = engine.evaluate(packet)
        rule = engine.get_rule(decision.rule_id) if decision.rule_id else None
        actual_prio = rule.priority if rule else None
        passed = decision.action == exp_action and actual_prio == exp_prio
        results.append({
            "ID": case_id,
            "Category": category,
            "Description": desc,
            "Packet": packet.describe(),
            "Default": default,
            "Expected": exp_action,
            "Actual": decision.action,
            "Expected Rule": "Default policy" if exp_prio is None else f"Priority {exp_prio}",
            "Actual Rule": "Default policy" if actual_prio is None else f"Priority {actual_prio}",
            "Result": "PASS" if passed else "FAIL",
        })
    return results


class TestFirewallCases(unittest.TestCase):
    def test_all_documented_cases(self):
        results = run_test_cases()
        self.assertGreaterEqual(len(results), 8)
        for row in results:
            with self.subTest(case=row["ID"], desc=row["Description"]):
                self.assertEqual(row["Actual"], row["Expected"])
                self.assertEqual(row["Actual Rule"], row["Expected Rule"])
                self.assertEqual(row["Result"], "PASS")

    def test_every_category_is_covered(self):
        categories = {row["Category"] for row in run_test_cases()}
        for needed in ["Allowed packet", "Denied packet", "Unknown source IP",
                       "Different protocols", "Rule ordering", "Overlapping rules",
                       "No matching rule", "Default ALLOW", "Default DENY"]:
            self.assertIn(needed, categories)


class TestEngineBehaviour(unittest.TestCase):
    def test_first_match_wins_and_rest_ignored(self):
        engine = build_engine("DENY", [(1, "ALLOW", "ANY", "ANY", "ANY"), (2, "DENY", "ANY", "ANY", "ANY")])
        decision = engine.evaluate(make_packet("1.2.3.4", SERVER, 80, "TCP"))
        self.assertEqual(decision.action, "ALLOW")
        self.assertEqual(decision.rule_id, 1)

    def test_execution_order_sorted_by_priority(self):
        engine = build_engine("DENY", [(30, "ALLOW", "ANY", "1", "ANY"),
                                       (10, "ALLOW", "ANY", "2", "ANY"),
                                       (20, "ALLOW", "ANY", "3", "ANY")])
        self.assertEqual([r.priority for r in engine.ordered_rules()], [10, 20, 30])

    def test_cidr_boundaries(self):
        engine = build_engine("DENY", [(10, "ALLOW", "192.168.1.0/24", "ANY", "ANY")])
        self.assertEqual(engine.evaluate(make_packet("192.168.1.255", SERVER, 80, "TCP")).action, "ALLOW")
        self.assertEqual(engine.evaluate(make_packet("192.168.2.1", SERVER, 80, "TCP")).action, "DENY")

    def test_icmp_ignores_port_and_never_matches_specific_port_rule(self):
        engine = build_engine("DENY", [(10, "ALLOW", "ANY", "80", "ANY")])
        packet = make_packet("1.2.3.4", SERVER, 80, "ICMP")
        self.assertIsNone(packet.dst_port)
        self.assertEqual(engine.evaluate(packet).action, "DENY")

    def test_delete_rule_changes_result(self):
        engine = FirewallEngine("ALLOW")
        rule = engine.add_rule("DENY", "ANY", 23, "ANY", 10)
        packet = make_packet("1.2.3.4", SERVER, 23, "TCP")
        self.assertEqual(engine.evaluate(packet, record=False).action, "DENY")
        self.assertTrue(engine.delete_rule(rule.rule_id))
        self.assertFalse(engine.delete_rule(rule.rule_id))
        self.assertEqual(engine.evaluate(packet, record=False).action, "ALLOW")

    def test_log_and_record_flag(self):
        engine = FirewallEngine("DENY")
        packet = make_packet("1.2.3.4", SERVER, 80, "TCP")
        engine.evaluate(packet, record=False)
        self.assertEqual(len(engine.log), 0)
        engine.evaluate(packet)
        self.assertEqual(len(engine.log), 1)
        self.assertTrue(engine.log[0].used_default)

    def test_trace_marks_applied_rule_and_skips_later_rules(self):
        engine = build_engine("DENY", EXAMPLE_RULES)
        rows = engine.trace(make_packet("192.168.1.10", SERVER, 23, "TCP"))
        self.assertTrue(rows[0]["Result"].startswith("MATCH"))
        self.assertTrue(all(r["Result"].startswith("Skipped") for r in rows[1:]))

    def test_trace_falls_back_to_default(self):
        engine = build_engine("ALLOW", EXAMPLE_RULES)
        rows = engine.trace(make_packet("203.0.113.9", SERVER, 9999, "TCP"))
        self.assertIn("default ALLOW", rows[-1]["Result"])

    def test_sample_traffic_valid_and_repeatable(self):
        first = generate_sample_packets(40, seed=7)
        second = generate_sample_packets(40, seed=7)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 40)
        for p in first:
            make_packet(p.src_ip, p.dst_ip, p.dst_port, p.protocol)

    def test_observations(self):
        engine = build_engine("ALLOW", EXAMPLE_RULES)
        self.assertEqual(security_observations(engine)[0][0], "info")  # empty log
        for p in generate_sample_packets(30, seed=1):
            engine.evaluate(p)
        notes = security_observations(engine)
        self.assertTrue(any("Default policy is ALLOW" in m for _, m in notes))


class TestValidation(unittest.TestCase):
    def test_bad_ips(self):
        for bad in ["999.1.1.1", "abc", "", "192.168.1", "1.2.3.4.5", "192.168.1.1/24x"]:
            with self.subTest(ip=bad):
                with self.assertRaises(ValidationError):
                    validate_ip(bad)

    def test_good_ip_is_trimmed(self):
        self.assertEqual(validate_ip(" 192.168.1.10 "), "192.168.1.10")

    def test_source_values(self):
        self.assertEqual(validate_source("any"), "ANY")
        self.assertEqual(validate_source("192.168.1.0/24"), "192.168.1.0/24")
        self.assertEqual(validate_source("192.168.1.77/24"), "192.168.1.0/24")
        for bad in ["192.168.1.0/33", "hello", "300.1.1.1"]:
            with self.subTest(src=bad):
                with self.assertRaises(ValidationError):
                    validate_source(bad)

    def test_ports(self):
        self.assertIsNone(validate_port("ANY"))
        self.assertEqual(validate_port("443"), 443)
        self.assertEqual(validate_port(65535), 65535)
        for bad in [0, 65536, -1, "abc", "80.5", "", True]:
            with self.subTest(port=bad):
                with self.assertRaises(ValidationError):
                    validate_port(bad)
        with self.assertRaises(ValidationError):
            validate_port("ANY", allow_any=False)

    def test_protocols(self):
        self.assertEqual(validate_protocol("tcp"), "TCP")
        self.assertEqual(validate_protocol("any"), "ANY")
        with self.assertRaises(ValidationError):
            validate_protocol("HTTP")
        with self.assertRaises(ValidationError):
            validate_protocol("ANY", allow_any=False)

    def test_priority_and_action(self):
        self.assertEqual(validate_priority("15"), 15)
        for bad in [0, 10000, "x"]:
            with self.subTest(priority=bad):
                with self.assertRaises(ValidationError):
                    validate_priority(bad)
        engine = FirewallEngine()
        with self.assertRaises(ValidationError):
            engine.add_rule("MAYBE", "ANY", "ANY", "ANY", 10)
        with self.assertRaises(ValidationError):
            FirewallEngine("BLOCK")

    def test_failed_add_does_not_change_rules(self):
        engine = FirewallEngine()
        with self.assertRaises(ValidationError):
            engine.add_rule("ALLOW", "bad-ip", 80, "TCP", 10)
        self.assertEqual(engine.ordered_rules(), [])

    def test_make_packet_validates(self):
        with self.assertRaises(ValidationError):
            make_packet("1.2.3.4", "nope", 80, "TCP")
        with self.assertRaises(ValidationError):
            make_packet("1.2.3.4", SERVER, 0, "TCP")
        with self.assertRaises(ValidationError):
            make_packet("1.2.3.4", SERVER, 80, "ANY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
