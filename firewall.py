"""
Key ideas
---------
* Rules are checked in execution order: LOWEST priority number first.
  (Priority 10 runs before priority 20.) Ties are broken by creation order.
* The FIRST rule that matches decides ALLOW or DENY. Later rules are ignored.
* If no rule matches, the DEFAULT POLICY (ALLOW or DENY) is applied.
* ICMP has no ports, so an ICMP packet has no port. It only matches rules
  whose port is ANY.
"""

from __future__ import annotations

import ipaddress
import random
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

ANY = "ANY"
PROTOCOLS = ("TCP", "UDP", "ICMP")
RULE_PROTOCOLS = PROTOCOLS + (ANY,)
ACTIONS = ("ALLOW", "DENY")

# Rules used when the app starts (priority, action, source, port, protocol).
EXAMPLE_RULES: List[Tuple[int, str, str, str, str]] = [
    (10, "DENY", "192.168.1.10", "23", "ANY"),
    (20, "ALLOW", "192.168.1.0/24", "80", "TCP"),
    (30, "ALLOW", "ANY", "443", "TCP"),
    (40, "DENY", "ANY", "22", "ANY"),
]

# Ports that are commonly attacked / considered risky (used for observations).
SENSITIVE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
class ValidationError(ValueError):
    """Raised when user input (IP, port, protocol, ...) is invalid."""


def validate_ip(value) -> str:
    """Return a clean IPv4 address string or raise ValidationError."""
    text = str(value).strip()
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise ValidationError(
            f"'{text}' is not a valid IPv4 address (example: 192.168.1.10)."
        )


def validate_source(value) -> str:
    """Rule source: 'ANY', a single IPv4 address, or a CIDR such as 192.168.1.0/24."""
    text = str(value).strip()
    if text.upper() == ANY:
        return ANY
    if "/" in text:
        try:
            return str(ipaddress.IPv4Network(text, strict=False))
        except ValueError:
            raise ValidationError(
                f"'{text}' is not a valid IPv4 network (example: 192.168.1.0/24)."
            )
    return validate_ip(text)


def validate_port(value, allow_any: bool = True) -> Optional[int]:
    """Return a port number (1-65535). Returns None for ANY when allow_any is True."""
    if value is None or (isinstance(value, str) and value.strip().upper() == ANY):
        if allow_any:
            return None
        raise ValidationError("A destination port is required (1-65535).")
    if isinstance(value, bool):
        raise ValidationError("Port must be a whole number between 1 and 65535.")
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValidationError(
            f"'{value}' is not a valid port. Use a whole number from 1 to 65535."
        )
    if not 1 <= number <= 65535:
        raise ValidationError(f"Port {number} is out of range. Use 1 to 65535.")
    return number


def validate_protocol(value, allow_any: bool = True) -> str:
    text = str(value).strip().upper()
    allowed = RULE_PROTOCOLS if allow_any else PROTOCOLS
    if text not in allowed:
        raise ValidationError(
            f"'{value}' is not a valid protocol. Choose one of: {', '.join(allowed)}."
        )
    return text


def validate_action(value) -> str:
    text = str(value).strip().upper()
    if text not in ACTIONS:
        raise ValidationError(f"Action must be ALLOW or DENY, not '{value}'.")
    return text


def validate_priority(value) -> int:
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValidationError("Priority must be a whole number (1 = checked first).")
    if not 1 <= number <= 9999:
        raise ValidationError("Priority must be between 1 and 9999.")
    return number


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Packet:
    src_ip: str
    dst_ip: str
    dst_port: Optional[int]  # None for ICMP
    protocol: str

    def describe(self) -> str:
        if self.dst_port is None:
            return f"{self.protocol} packet {self.src_ip} -> {self.dst_ip}"
        return (
            f"{self.protocol} packet {self.src_ip} -> {self.dst_ip}:{self.dst_port}"
        )


def make_packet(src_ip, dst_ip, dst_port, protocol) -> Packet:
    """Validate raw input and build a Packet. ICMP ignores the port."""
    src = validate_ip(src_ip)
    dst = validate_ip(dst_ip)
    proto = validate_protocol(protocol, allow_any=False)
    port = None if proto == "ICMP" else validate_port(dst_port, allow_any=False)
    return Packet(src, dst, port, proto)


@dataclass
class Rule:
    rule_id: int
    priority: int
    action: str
    source: str = ANY  # "ANY", "1.2.3.4" or "1.2.3.0/24"
    port: Optional[int] = None  # None means ANY
    protocol: str = ANY
    description: str = ""

    @property
    def port_text(self) -> str:
        return ANY if self.port is None else str(self.port)

    def summary(self) -> str:
        return f"{self.action} {self.source} -> port {self.port_text} / {self.protocol}"

    def label(self) -> str:
        return f"Rule #{self.rule_id} (priority {self.priority}): {self.summary()}"

    def check_parts(self, packet: Packet) -> Tuple[bool, bool, bool]:
        """Return (source_ok, port_ok, protocol_ok) for the given packet."""
        if self.source == ANY:
            source_ok = True
        else:
            network = ipaddress.IPv4Network(self.source, strict=False)
            source_ok = ipaddress.IPv4Address(packet.src_ip) in network
        port_ok = self.port is None or self.port == packet.dst_port
        proto_ok = self.protocol == ANY or self.protocol == packet.protocol
        return source_ok, port_ok, proto_ok

    def matches(self, packet: Packet) -> bool:
        return all(self.check_parts(packet))


@dataclass
class Decision:
    packet: Packet
    action: str
    rule_id: Optional[int]
    rule_label: str
    reason: str
    used_default: bool
    timestamp: datetime

    def to_record(self) -> Dict[str, str]:
        return {
            "Time": self.timestamp.strftime("%H:%M:%S"),
            "Source IP": self.packet.src_ip,
            "Destination IP": self.packet.dst_ip,
            "Port": "-" if self.packet.dst_port is None else str(self.packet.dst_port),
            "Protocol": self.packet.protocol,
            "Action": self.action,
            "Matched Rule": self.rule_label,
            "Reason": self.reason,
        }


# --------------------------------------------------------------------------
# Firewall engine
# --------------------------------------------------------------------------
class FirewallEngine:
    """Holds the rules, the default policy and the log of evaluated packets."""

    def __init__(self, default_policy: str = "DENY"):
        self.default_policy = validate_action(default_policy)
        self._rules: List[Rule] = []
        self._next_id = 1
        self.log: List[Decision] = []

    # ---- rule management -------------------------------------------------
    def set_default_policy(self, policy: str) -> None:
        self.default_policy = validate_action(policy)

    def add_rule(
        self,
        action,
        source=ANY,
        port=ANY,
        protocol=ANY,
        priority=100,
        description: str = "",
    ) -> Rule:
        rule = Rule(
            rule_id=self._next_id,
            priority=validate_priority(priority),
            action=validate_action(action),
            source=validate_source(source),
            port=validate_port(port, allow_any=True),
            protocol=validate_protocol(protocol, allow_any=True),
            description=str(description).strip(),
        )
        self._rules.append(rule)
        self._next_id += 1
        return rule

    def delete_rule(self, rule_id: int) -> bool:
        for rule in self._rules:
            if rule.rule_id == rule_id:
                self._rules.remove(rule)
                return True
        return False

    def clear_rules(self) -> None:
        self._rules.clear()

    def load_example_rules(self) -> None:
        self.clear_rules()
        for priority, action, source, port, protocol in EXAMPLE_RULES:
            self.add_rule(action, source, port, protocol, priority)

    def ordered_rules(self) -> List[Rule]:
        """Rules in execution order: lowest priority number first, then oldest first."""
        return sorted(self._rules, key=lambda r: (r.priority, r.rule_id))

    def get_rule(self, rule_id: int) -> Optional[Rule]:
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    # ---- packet evaluation -----------------------------------------------
    def evaluate(self, packet: Packet, record: bool = True) -> Decision:
        """Apply the FIRST matching rule, otherwise the default policy."""
        ordered = self.ordered_rules()
        decision: Optional[Decision] = None

        for checked, rule in enumerate(ordered):
            if rule.matches(packet):
                decision = self._decision_from_rule(packet, rule, checked)
                break

        if decision is None:
            decision = self._decision_from_default(packet, len(ordered))

        if record:
            self.log.append(decision)
        return decision

    def trace(self, packet: Packet) -> List[Dict[str, str]]:
        """Step-by-step view of how each rule was checked (for teaching/demo)."""
        rows = []
        applied = False
        for position, rule in enumerate(self.ordered_rules(), start=1):
            if applied:
                result = "Skipped (earlier rule already matched)"
                parts = ("-", "-", "-")
            else:
                s_ok, p_ok, pr_ok = rule.check_parts(packet)
                parts = tuple("Yes" if ok else "No" for ok in (s_ok, p_ok, pr_ok))
                if s_ok and p_ok and pr_ok:
                    result = f"MATCH -> {rule.action} applied"
                    applied = True
                else:
                    result = "No match"
            rows.append(
                {
                    "Order": position,
                    "Rule ID": rule.rule_id,
                    "Priority": rule.priority,
                    "Rule": rule.summary(),
                    "Source OK": parts[0],
                    "Port OK": parts[1],
                    "Protocol OK": parts[2],
                    "Result": result,
                }
            )
        if not applied:
            rows.append(
                {
                    "Order": len(rows) + 1,
                    "Rule ID": "-",
                    "Priority": "-",
                    "Rule": f"Default policy ({self.default_policy})",
                    "Source OK": "-",
                    "Port OK": "-",
                    "Protocol OK": "-",
                    "Result": f"No rule matched -> default {self.default_policy} applied",
                }
            )
        return rows

    def clear_log(self) -> None:
        self.log.clear()

    # ---- helpers -----------------------------------------------------------
    def _decision_from_rule(self, packet: Packet, rule: Rule, checked: int) -> Decision:
        src_part = (
            "any source address"
            if rule.source == ANY
            else f"source {packet.src_ip} is covered by {rule.source}"
        )
        if rule.port is None:
            port_part = "any port"
        else:
            port_part = f"destination port {packet.dst_port} equals {rule.port}"
        proto_part = (
            "any protocol" if rule.protocol == ANY else f"protocol is {rule.protocol}"
        )
        outcome = "allowed through" if rule.action == "ALLOW" else "blocked"
        reason = (
            f"{packet.describe()} matched Rule #{rule.rule_id} (priority {rule.priority}), "
            f"the first rule that fits: {src_part}; {port_part}; {proto_part}. "
            f"{checked} earlier rule(s) did not match, and later rules are not checked. "
            f"Rule action is {rule.action}, so the packet is {outcome}."
        )
        return Decision(
            packet, rule.action, rule.rule_id, rule.label(), reason, False, datetime.now()
        )

    def _decision_from_default(self, packet: Packet, rules_checked: int) -> Decision:
        outcome = "allowed through" if self.default_policy == "ALLOW" else "blocked"
        reason = (
            f"{packet.describe()} did not match any of the {rules_checked} rule(s), "
            f"so the default policy ({self.default_policy}) was applied and the packet is {outcome}."
        )
        return Decision(
            packet,
            self.default_policy,
            None,
            f"Default policy ({self.default_policy})",
            reason,
            True,
            datetime.now(),
        )


# --------------------------------------------------------------------------
# Sample traffic + analysis helpers
# --------------------------------------------------------------------------
def generate_sample_packets(count: int = 50, seed: Optional[int] = None) -> List[Packet]:
    """Create fictional packets. Uses documentation/private IP ranges only."""
    rng = random.Random(seed)
    sources = [
        "192.168.1.10", "192.168.1.25", "192.168.1.77", "10.0.0.5",
        "172.16.4.9", "203.0.113.50", "198.51.100.23", "45.33.12.8",
    ]
    source_weights = [4, 5, 4, 3, 2, 4, 3, 2]
    destinations = ["10.0.0.10", "10.0.0.20", "10.0.0.30"]
    ports = [80, 443, 22, 23, 53, 3389, 8080, 21, 25]
    port_weights = [8, 8, 5, 3, 3, 2, 2, 1, 1]
    protocols = ["TCP", "UDP", "ICMP"]
    protocol_weights = [6, 3, 1]

    packets = []
    for _ in range(max(0, int(count))):
        proto = rng.choices(protocols, protocol_weights)[0]
        port = None if proto == "ICMP" else rng.choices(ports, port_weights)[0]
        packets.append(
            Packet(
                rng.choices(sources, source_weights)[0],
                rng.choice(destinations),
                port,
                proto,
            )
        )
    return packets


def blocked_by_rule(engine: FirewallEngine) -> Dict[str, int]:
    """Number of DENY decisions per rule label (rules with no hits show 0)."""
    counts: Counter = Counter()
    for rule in engine.ordered_rules():
        counts[rule.label()] += 0
    counts[f"Default policy ({engine.default_policy})"] += 0
    for decision in engine.log:
        if decision.action == "DENY":
            counts[decision.rule_label] += 1
    return dict(counts)


def security_observations(engine: FirewallEngine) -> List[Tuple[str, str]]:
    """Plain-English findings. Returns (level, message); level = good/warning/info."""
    log = engine.log
    if not log:
        return [("info", "No packets have been simulated yet. Run the packet simulator "
                         "or generate sample traffic to see observations.")]

    notes: List[Tuple[str, str]] = []
    total = len(log)
    denied = [d for d in log if d.action == "DENY"]
    block_pct = 100 * len(denied) / total

    if engine.default_policy == "ALLOW":
        notes.append(("warning", "Default policy is ALLOW: any traffic not covered by a rule "
                                 "passes through. Real firewalls normally use default DENY."))
    else:
        notes.append(("good", "Default policy is DENY: traffic is blocked unless a rule "
                              "explicitly allows it (the safer approach)."))

    if block_pct >= 50:
        notes.append(("warning", f"{block_pct:.0f}% of traffic was blocked. Check that "
                                 "legitimate services are not being denied by mistake."))
    elif block_pct == 0:
        notes.append(("warning", "No packets were blocked. The rule set may be too permissive."))
    else:
        notes.append(("info", f"{block_pct:.0f}% of the traffic was blocked."))

    blocked_sources = Counter(d.packet.src_ip for d in denied)
    if blocked_sources:
        ip, hits = blocked_sources.most_common(1)[0]
        notes.append(("info", f"Most blocked source: {ip} ({hits} blocked packet(s)). "
                              "Repeated blocked attempts from one address can indicate scanning "
                              "or a misconfigured device."))

    for port, name in SENSITIVE_PORTS.items():
        allowed_hits = sum(1 for d in log if d.action == "ALLOW" and d.packet.dst_port == port)
        denied_hits = sum(1 for d in denied if d.packet.dst_port == port)
        if allowed_hits:
            notes.append(("warning", f"{name} (port {port}) traffic was ALLOWED {allowed_hits} "
                                     "time(s). This port is a common attack target."))
        elif denied_hits:
            notes.append(("good", f"{name} (port {port}) traffic was blocked {denied_hits} time(s)."))

    default_hits = sum(1 for d in log if d.used_default)
    if default_hits:
        notes.append(("info", f"{default_hits} packet(s) ({100 * default_hits / total:.0f}%) matched no "
                              "rule and fell back to the default policy. Consider adding explicit "
                              "rules for traffic you expect."))

    used_ids = {d.rule_id for d in log if d.rule_id is not None}
    unused = [r for r in engine.ordered_rules() if r.rule_id not in used_ids]
    if unused:
        ids = ", ".join(f"#{r.rule_id}" for r in unused)
        notes.append(("info", f"Rule(s) {ids} never matched any packet. They may be unnecessary "
                              "or shadowed by an earlier rule."))

    for rule in engine.ordered_rules():
        if rule.action == "ALLOW" and rule.source == ANY and rule.port is None and rule.protocol == ANY:
            notes.append(("warning", f"Rule #{rule.rule_id} allows ALL traffic from anywhere. "
                                     "Any rule after it can never be reached."))
    return notes
