"""Business tests for offline ordered ACL first-hit diffing.

The production engine works with symbolic boxes and never enumerates
packets.  These tests cross-check it against an *independent* brute-force
model that evaluates the first-hit rule packet by packet over a deliberately
small universe; the two share no code beyond the validated rule dictionaries.
"""
import hashlib
import ipaddress
import json
import random
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ipv4_leases.acl import (
    DST_SPACE, MAX_RULES, PORT_COUNT, PROTO_ANY, PROTO_TCP, PROTO_UDP,
    build_report, parse_rules, strict_cidr, subtract_box, intersect_boxes,
    box_volume, normalize, _try_merge,
)
from ipv4_leases.pool import Pool

# A small pool: 192.0.2.8/29 has six usable hosts, .9..14.
POOL_CIDR = '192.0.2.8/29'
POOL_HOSTS = list(ipaddress.ip_network(POOL_CIDR).hosts())
# The brute-force destination universe and port window stay tiny on purpose.
DST_HOSTS = [ipaddress.IPv4Address('198.51.100.%d' % i) for i in range(5)]
PORTS = [0, 1, 7, 80, 81, 82, 65535]
PROTOS = ('tcp', 'udp')
PROTO_BIT = {'tcp': PROTO_TCP, 'udp': PROTO_UDP}


def rule(rid, src, dst, protocol, ports, action):
    return {'id': rid, 'src': src, 'dst': dst, 'protocol': protocol,
            'ports': list(ports), 'action': action}


class BruteForceModel:
    """Independent packet-by-packet first-hit model on a small universe.

    Matching is reimplemented from the contract with plain range tests and a
    linear rule scan; it never imports the production region engine.
    """

    def __init__(self, rules, src_hosts, dst_hosts, ports):
        self.rules = parse_rules(rules)
        self.src_hosts = [int(a) for a in src_hosts]
        self.dst_hosts = [int(a) for a in dst_hosts]
        self.ports = list(ports)

    def first_hit(self, src, dst, protocol, port):
        bit = PROTO_BIT[protocol]
        for item in self.rules:
            (_id, action, s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi) = item
            if (s_lo <= src <= s_hi and d_lo <= dst <= d_hi
                    and protos & bit and p_lo <= port <= p_hi):
                return _id
        return None

    def label_map(self):
        labels = {}
        for src in self.src_hosts:
            for dst in self.dst_hosts:
                for protocol in PROTOS:
                    for port in self.ports:
                        labels[(src, dst, protocol, port)] = self.first_hit(
                            src, dst, protocol, port)
        return labels

    def usage(self):
        """Per-rule and default raw/effective counts over the small universe.

        ``raw`` counts every packet each rule matches regardless of earlier
        rules (no break); ``effective`` counts only first-hit packets.  The
        two are intentionally computed independently.
        """
        raw = {item[0]: 0 for item in self.rules}
        effective = {item[0]: 0 for item in self.rules}
        labels = self.label_map()
        for label in labels.values():
            if label is not None:
                effective[label] += 1
        for src in self.src_hosts:
            for dst in self.dst_hosts:
                for protocol in PROTOS:
                    bit = PROTO_BIT[protocol]
                    for port in self.ports:
                        for item in self.rules:
                            (_id, action, s_lo, s_hi, d_lo, d_hi,
                             protos, p_lo, p_hi) = item
                            if (s_lo <= src <= s_hi and d_lo <= dst <= d_hi
                                    and protos & bit and p_lo <= port <= p_hi):
                                raw[_id] += 1  # no break: raw counts all matches
        default_effective = sum(1 for v in labels.values() if v is None)
        return raw, effective, default_effective


def small_cidrs():
    """Aligned, in-universe CIDRs usable by both the engine and brute force."""
    srcs = ['192.0.2.8/29', '192.0.2.10/31', '192.0.2.9/32',
            '192.0.2.12/32', '0.0.0.0/0', '203.0.113.0/24']
    dsts = ['198.51.100.0/29', '198.51.100.0/31', '198.51.100.2/32',
            '198.51.100.4/32', '0.0.0.0/0', '192.0.2.0/24']
    return srcs, dsts


def linear_first_hit(parsed, src, dst, protocol, port):
    """Contract-faithful linear first-hit scan, independent of the engine."""
    bit = PROTO_BIT[protocol]
    for item in parsed:
        (_id, action, s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi) = item
        if (s_lo <= src <= s_hi and d_lo <= dst <= d_hi
                and protos & bit and p_lo <= port <= p_hi):
            return _id
    return None


def projected_raw(item, src_hosts, dst_hosts, ports):
    """Raw match count of one rule over the finite brute-force universe."""
    (_id, action, s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi) = item
    srcs = [s for s in (int(h) for h in src_hosts) if s_lo <= s <= s_hi]
    dsts = [d for d in (int(h) for h in dst_hosts) if d_lo <= d <= d_hi]
    ports_in = [p for p in ports if p_lo <= p <= p_hi]
    return len(srcs) * len(dsts) * bin(protos).count('1') * len(ports_in)


class Acceptance(unittest.TestCase):
    """The contract's /32 acceptance example, asserted value by value."""

    def setUp(self):
        self.before = [rule('B', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 81), 'allow')]
        self.after = [
            rule('D', '0.0.0.0/0', '0.0.0.0/1', 'tcp', (81, 81), 'deny'),
            rule('A', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (81, 82), 'allow')]
        self.report = build_report('192.0.2.9/32', 0, self.before, self.after)

    def test_report_shape_and_totals(self):
        self.assertEqual(set(self.report), {
            'cidr', 'clock', 'total_packets', 'newly_allowed',
            'newly_denied', 'before', 'after', 'transitions'})
        self.assertEqual(self.report['cidr'], '192.0.2.9/32')
        self.assertEqual(self.report['clock'], 0)
        self.assertEqual(self.report['total_packets'], 2 ** 49)
        self.assertEqual(self.report['newly_allowed'], 2 ** 32)
        self.assertEqual(self.report['newly_denied'], 2 ** 32 + 2 ** 31)

    def test_per_rule_usage(self):
        d = next(row for row in self.report['after'] if row['id'] == 'D')
        a = next(row for row in self.report['after'] if row['id'] == 'A')
        self.assertEqual(d, {'id': 'D', 'action': 'deny',
                             'raw_packets': 2 ** 31, 'effective_packets': 2 ** 31,
                             'shadowed_packets': 0})
        self.assertEqual(a, {'id': 'A', 'action': 'allow',
                             'raw_packets': 2 ** 33,
                             'effective_packets': 2 ** 33 - 2 ** 31,
                             'shadowed_packets': 2 ** 31})
        b = next(row for row in self.report['before'] if row['id'] == 'B')
        self.assertEqual(b['action'], 'allow')
        self.assertEqual(b['effective_packets'], 2 ** 33)
        for version in (self.report['before'], self.report['after']):
            self.assertEqual(version[-1]['id'], None)
            self.assertEqual(version[-1]['action'], 'deny')
            self.assertEqual(version[-1]['raw_packets'], 2 ** 49)
            self.assertEqual(sum(r['effective_packets'] for r in version), 2 ** 49)
            for row in version:
                self.assertEqual(row['raw_packets'],
                                 row['effective_packets'] + row['shadowed_packets'])

    def test_transition_counts_and_order(self):
        pairs = {(t['before_rule'], t['after_rule']): t
                 for t in self.report['transitions']}
        self.assertEqual(pairs[('B', 'D')]['packets'], 2 ** 31)
        self.assertEqual(pairs[('B', 'A')]['packets'], 2 ** 31)
        self.assertEqual(pairs[('B', None)]['packets'], 2 ** 32)
        self.assertEqual(pairs[(None, 'A')]['packets'], 2 ** 32)
        covered = 2 ** 31 + 2 ** 31 + 2 ** 32 + 2 ** 32
        self.assertEqual(pairs[(None, None)]['packets'], 2 ** 49 - covered)
        self.assertEqual(sum(t['packets'] for t in self.report['transitions']),
                         2 ** 49)
        # Ordering: before_rule then after_rule, null after every string.
        self.assertEqual([(t['before_rule'], t['after_rule'])
                          for t in self.report['transitions']],
                         [('B', 'A'), ('B', 'D'), ('B', None),
                          (None, 'A'), (None, None)])
        for t in self.report['transitions']:
            self.assertGreater(t['packets'], 0)
            self.assertEqual(set(t), {'before_rule', 'after_rule',
                                      'before_action', 'after_action',
                                      'packets', 'witness'})
            self.assertEqual(set(t['witness']), {'src', 'dst', 'protocol', 'port'})

    def test_minimum_witness_of_b_d(self):
        pairs = {(t['before_rule'], t['after_rule']): t
                 for t in self.report['transitions']}
        self.assertEqual(pairs[('B', 'D')]['witness'], {
            'src': '192.0.2.9', 'dst': '0.0.0.0',
            'protocol': 'tcp', 'port': 81})

    def test_witnesses_really_belong_to_their_combination(self):
        before = BruteForceModel(self.before, [ipaddress.IPv4Address('192.0.2.9')],
                                 [ipaddress.IPv4Address('0.0.0.0')], [80, 81, 82])
        after = BruteForceModel(self.after, [ipaddress.IPv4Address('192.0.2.9')],
                                [ipaddress.IPv4Address('0.0.0.0')], [80, 81, 82])
        for transition in self.report['transitions']:
            w = transition['witness']
            src = int(ipaddress.IPv4Address(w['src']))
            dst = int(ipaddress.IPv4Address(w['dst']))
            self.assertEqual(before.first_hit(src, dst, w['protocol'], w['port']),
                             transition['before_rule'])
            self.assertEqual(after.first_hit(src, dst, w['protocol'], w['port']),
                             transition['after_rule'])


class RegionAlgebra(unittest.TestCase):
    """Low-level exactness properties of the symbolic box operations."""

    def test_subtract_box_is_exact_and_disjoint(self):
        rnd = random.Random(20261118)
        for _ in range(20000):
            def interval(hi=14):
                lo = rnd.randrange(0, hi)
                return lo, rnd.randrange(lo, hi)
            a = (interval()[0], interval()[1], interval()[0], interval()[1],
                 rnd.choice((1, 2, 3)), interval(9)[0], interval(9)[1])
            b = (interval()[0], interval()[1], interval()[0], interval()[1],
                 rnd.choice((1, 2, 3)), interval(9)[0], interval(9)[1])
            remainder = subtract_box(a, b)
            for i in range(len(remainder)):
                for j in range(i + 1, len(remainder)):
                    self.assertIsNone(intersect_boxes(remainder[i], remainder[j]))
            common = intersect_boxes(a, b)
            common_volume = box_volume(common) if common else 0
            self.assertEqual(
                box_volume(a),
                common_volume + sum(box_volume(x) for x in remainder))

    def test_full_cover_and_proto_split(self):
        body = (0, 9, 0, 9, PROTO_ANY, 0, 9)
        self.assertEqual(subtract_box(body, body), [])
        self.assertEqual(
            subtract_box(body, (0, 9, 0, 9, PROTO_TCP, 0, 9)),
            [(0, 9, 0, 9, PROTO_UDP, 0, 9)])
        # Disjoint cutter leaves the box untouched.
        self.assertEqual(
            subtract_box(body, (100, 101, 0, 9, PROTO_ANY, 0, 9)), [body])

    def test_merge_requires_equality_on_all_other_dimensions(self):
        # Regression: two boxes whose ports merely touch but whose source and
        # destination ranges differ must never collapse into one box.
        one = (1, 5, 5, 9, PROTO_UDP, 7, 9)
        two = (0, 11, 5, 11, PROTO_UDP, 0, 8)
        self.assertIsNone(_try_merge(one, two))
        # A genuine port merge shares every other dimension exactly.
        left = (0, 4, 0, 4, PROTO_TCP, 0, 8)
        right = (0, 4, 0, 4, PROTO_TCP, 9, 20)
        self.assertEqual(_try_merge(left, right),
                         (0, 4, 0, 4, PROTO_TCP, 0, 20))
        # Different proto masks never merge even with identical ranges.
        self.assertIsNone(_try_merge(
            (0, 4, 0, 4, PROTO_TCP, 0, 8),
            (0, 4, 0, 4, PROTO_UDP, 9, 20)))

    def test_normalize_preserves_volume_and_disjointness(self):
        rnd = random.Random(31337)

        def interval(hi=14):
            lo = rnd.randrange(0, hi)
            return lo, rnd.randrange(lo, hi)

        for _ in range(2000):
            region = []
            for _ in range(rnd.randrange(1, 9)):
                s, d, p = interval(), interval(), interval(10)
                box = (s[0], s[1], d[0], d[1], rnd.choice((1, 2, 3)), p[0], p[1])
                fresh = [box]
                for cover in region:  # keep the region disjoint, engine-style
                    fresh = sum((subtract_box(f, cover) for f in fresh), [])
                region = normalize(region + fresh)
            volume = sum(box_volume(b) for b in region)
            merged = normalize(region)
            self.assertEqual(sum(box_volume(b) for b in merged), volume)
            for i in range(len(merged)):
                for j in range(i + 1, len(merged)):
                    self.assertIsNone(intersect_boxes(merged[i], merged[j]))


class BruteForceCrossCheck(unittest.TestCase):
    """Random small policies: engine vs. an independent packet-by-packet model."""

    def _small_rules(self, rnd, count):
        srcs, dsts = small_cidrs()
        rules, ids = [], set()
        while len(rules) < count:
            rid = 'id%d' % rnd.randrange(100000)
            if rid in ids:
                continue
            ids.add(rid)
            lo = rnd.choice(PORTS)
            hi = rnd.choice([p for p in PORTS if p >= lo])
            rules.append(rule(rid, rnd.choice(srcs), rnd.choice(dsts),
                              rnd.choice(('tcp', 'udp', 'any')), (lo, hi),
                              rnd.choice(('allow', 'deny'))))
        return rules

    def test_random_policies_match_brute_force(self):
        rnd = random.Random(424242)
        for trial in range(60):
            before = self._small_rules(rnd, rnd.randrange(0, 12))
            after = self._small_rules(rnd, rnd.randrange(0, 12))
            report = build_report(POOL_CIDR, 7, before, after)
            parsed_before = parse_rules(before)
            parsed_after = parse_rules(after)
            bf_before = BruteForceModel(before, POOL_HOSTS, DST_HOSTS, PORTS)
            bf_after = BruteForceModel(after, POOL_HOSTS, DST_HOSTS, PORTS)
            labels_before = bf_before.label_map()
            labels_after = bf_after.label_map()

            # Every brute-force combination must appear in the engine report,
            # and its minimum packet in the universe must match the engine
            # witness whenever the witness falls inside the universe.
            expected = {}
            for packet, bid in labels_before.items():
                expected.setdefault((bid, labels_after[packet]), []).append(packet)
            engine_pairs = {(t['before_rule'], t['after_rule']): t
                            for t in report['transitions']}
            self.assertTrue(set(expected) <= set(engine_pairs))
            universe_src = {int(h) for h in POOL_HOSTS}
            universe_dst = {int(h) for h in DST_HOSTS}
            for key, packets in expected.items():
                minimum = min(packets, key=lambda p: (
                    p[0], p[1], 0 if p[2] == 'tcp' else 1, p[3]))
                w = engine_pairs[key]['witness']
                wsrc = int(ipaddress.IPv4Address(w['src']))
                wdst = int(ipaddress.IPv4Address(w['dst']))
                if (wsrc in universe_src and wdst in universe_dst
                        and w['port'] in set(PORTS)):
                    self.assertEqual(w, {
                        'src': str(ipaddress.IPv4Address(minimum[0])),
                        'dst': str(ipaddress.IPv4Address(minimum[1])),
                        'protocol': minimum[2], 'port': minimum[3]})

            # Every reported witness is a genuine first-hit packet under the
            # independent linear scan, for both versions.
            for transition in report['transitions']:
                w = transition['witness']
                src = int(ipaddress.IPv4Address(w['src']))
                dst = int(ipaddress.IPv4Address(w['dst']))
                self.assertEqual(
                    linear_first_hit(parsed_before, src, dst, w['protocol'], w['port']),
                    transition['before_rule'])
                self.assertEqual(
                    linear_first_hit(parsed_after, src, dst, w['protocol'], w['port']),
                    transition['after_rule'])

            # Brute-force raw and effective counts, including the default.
            for bf, usage_rows, parsed in (
                    (bf_before, report['before'], parsed_before),
                    (bf_after, report['after'], parsed_after)):
                raw_bf, eff_bf, default_bf = bf.usage()
                labels = bf.label_map()
                by_id = {item[0]: item for item in parsed}
                for row in usage_rows[:-1]:
                    self.assertEqual(
                        projected_raw(by_id[row['id']], POOL_HOSTS, DST_HOSTS, PORTS),
                        raw_bf[row['id']])
                    self.assertEqual(
                        sum(1 for v in labels.values() if v == row['id']),
                        eff_bf[row['id']])
                self.assertEqual(
                    sum(1 for v in labels.values() if v is None), default_bf)

            # The symbolic engine partitions the whole domain exactly once.
            self.assertEqual(
                sum(t['packets'] for t in report['transitions']),
                report['total_packets'])
            self.assertEqual(
                sum(r['effective_packets'] for r in report['before']),
                report['total_packets'])
            self.assertEqual(
                sum(r['effective_packets'] for r in report['after']),
                report['total_packets'])
            for row in report['before'] + report['after']:
                self.assertEqual(
                    row['raw_packets'],
                    row['effective_packets'] + row['shadowed_packets'])

    def test_brute_force_universe_size_and_default_residual(self):
        # The default-default residual equals total minus the brute-force
        # universe whenever every enumerated packet falls to default deny.
        empty = build_report(POOL_CIDR, 1, [], [])
        universe_packets = len(POOL_HOSTS) * len(DST_HOSTS) * 2 * len(PORTS)
        self.assertEqual(empty['total_packets'],
                         len(POOL_HOSTS) * DST_SPACE * 2 * PORT_COUNT)
        self.assertEqual(empty['transitions'][0]['packets'], empty['total_packets'])
        self.assertGreater(empty['total_packets'], universe_packets)
        self.assertEqual(empty['transitions'][0]['witness'], {
            'src': str(POOL_HOSTS[0]), 'dst': '0.0.0.0',
            'protocol': 'tcp', 'port': 0})


class BusinessSemantics(unittest.TestCase):
    def _total(self, cidr):
        hosts = len(list(ipaddress.ip_network(cidr).hosts()))
        return hosts * DST_SPACE * 2 * PORT_COUNT

    def test_empty_policies_are_legal(self):
        for cidr in ('192.0.2.8/31', '192.0.2.9/32', '10.10.0.0/20'):
            report = build_report(cidr, 3, [], [])
            self.assertEqual(report['total_packets'], self._total(cidr))
            self.assertEqual(len(report['before']), 1)
            self.assertEqual(report['before'][0], {
                'id': None, 'action': 'deny',
                'raw_packets': report['total_packets'],
                'effective_packets': report['total_packets'],
                'shadowed_packets': 0})
            self.assertEqual(report['newly_allowed'], 0)
            self.assertEqual(report['newly_denied'], 0)

    def test_rule_rename_same_action_keeps_transition(self):
        r1 = [rule('old', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 80), 'allow')]
        r2 = [rule('new', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 80), 'allow')]
        report = build_report('192.0.2.9/32', 0, r1, r2)
        self.assertEqual(len(report['transitions']), 2)
        changed = next(t for t in report['transitions']
                       if t['before_rule'] == 'old' and t['after_rule'] == 'new')
        self.assertEqual(changed['before_action'], 'allow')
        self.assertEqual(changed['after_action'], 'allow')
        self.assertEqual(changed['packets'], 2 ** 32)
        self.assertEqual(report['newly_allowed'], 0)
        self.assertEqual(report['newly_denied'], 0)

    def test_equal_allow_totals_with_bidirectional_change(self):
        # Both versions allow exactly one tcp/80 destination /8 each, but
        # different /8 blocks: equal allow totals, yet traffic changes both
        # ways and the report must capture both directions.
        before = [rule('b', '0.0.0.0/0', '1.0.0.0/8', 'tcp', (80, 80), 'allow')]
        after = [rule('a', '0.0.0.0/0', '2.0.0.0/8', 'tcp', (80, 80), 'allow')]
        report = build_report('192.0.2.9/32', 0, before, after)
        block = 2 ** 24
        self.assertEqual(report['newly_allowed'], block)
        self.assertEqual(report['newly_denied'], block)
        pairs = {(t['before_rule'], t['after_rule']): t
                 for t in report['transitions']}
        self.assertEqual(pairs[('b', None)]['packets'], block)
        self.assertEqual(pairs[(None, 'a')]['packets'], block)

    def test_early_deny_shadows_later_allow(self):
        rules = [
            rule('d', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 80), 'deny'),
            rule('a', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 80), 'allow')]
        report = build_report('192.0.2.9/32', 0, rules, [])
        rows = {r['id']: r for r in report['before']}
        self.assertEqual(rows['d']['effective_packets'], 2 ** 32)
        self.assertEqual(rows['a']['effective_packets'], 0)
        self.assertEqual(rows['a']['shadowed_packets'], rows['a']['raw_packets'])

    def test_reorder_overlapping_different_actions_changes_result(self):
        x = rule('x', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 81), 'allow')
        y = rule('y', '0.0.0.0/0', '0.0.0.0/1', 'tcp', (81, 81), 'deny')
        one = build_report('192.0.2.9/32', 0, [x, y], [])
        two = build_report('192.0.2.9/32', 0, [y, x], [])
        rows_one = {r['id']: r for r in one['before']}
        rows_two = {r['id']: r for r in two['before']}
        # With allow first, deny is fully shadowed; reversed, deny wins the
        # /1:81 region and the allow loses exactly that slice.
        self.assertEqual(rows_one['y']['effective_packets'], 0)
        self.assertEqual(rows_two['y']['effective_packets'], 2 ** 31)
        self.assertEqual(rows_two['x']['effective_packets'],
                         rows_one['x']['effective_packets'] - 2 ** 31)

    def test_rule_source_completely_outside_pool(self):
        rules = [rule('out', '203.0.113.0/24', '0.0.0.0/0', 'any',
                      (0, 65535), 'allow')]
        report = build_report('192.0.2.9/32', 0, rules, [])
        row = report['before'][0]
        self.assertEqual(row['id'], 'out')
        self.assertEqual(row['raw_packets'], 0)
        self.assertEqual(row['effective_packets'], 0)
        self.assertEqual(row['shadowed_packets'], 0)
        self.assertEqual(report['before'][-1]['effective_packets'],
                         report['total_packets'])

    def test_slash31_slash32_and_protocol_any(self):
        rules = [rule('any', '0.0.0.0/0', '0.0.0.0/0', 'any', (0, 65535), 'allow')]
        r31 = build_report('192.0.2.8/31', 0, rules, [])
        r32 = build_report('192.0.2.9/32', 0, rules, [])
        self.assertEqual(r31['before'][0]['effective_packets'],
                         2 * DST_SPACE * 2 * PORT_COUNT)
        self.assertEqual(r32['before'][0]['effective_packets'],
                         DST_SPACE * 2 * PORT_COUNT)
        # Both default rows retain zero effective coverage.
        self.assertEqual(r31['before'][-1]['effective_packets'], 0)
        self.assertEqual(r32['before'][-1]['effective_packets'], 0)

    def test_full_dst_and_full_port_spans_plus_endpoints(self):
        rules = [
            rule('all', '0.0.0.0/0', '0.0.0.0/0', 'any', (0, 65535), 'allow'),
            rule('edge', '0.0.0.0/0', '255.255.255.255/32', 'udp',
                 (65535, 65535), 'deny')]
        report = build_report('192.0.2.9/32', 0, rules, [])
        rows = {r['id']: r for r in report['before']}
        # The broad allow covers the whole domain; the edge rule is shadowed.
        self.assertEqual(rows['all']['effective_packets'], 2 ** 49)
        self.assertEqual(rows['edge']['effective_packets'], 0)
        self.assertEqual(rows['edge']['raw_packets'], 1)

    def test_input_order_is_priority_never_resorted(self):
        # A broad deny first must dominate a narrower allow regardless of id.
        rules = [rule('zzz', '0.0.0.0/0', '0.0.0.0/0', 'udp', (0, 100), 'deny'),
                 rule('aaa', '0.0.0.0/0', '10.0.0.0/8', 'udp', (0, 100), 'allow')]
        report = build_report('192.0.2.9/32', 0, rules, [])
        self.assertEqual([r['id'] for r in report['before'][:2]], ['zzz', 'aaa'])
        self.assertEqual(report['before'][1]['effective_packets'], 0)

    def test_identifiers_may_repeat_across_versions(self):
        shared = rule('same', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 80), 'allow')
        report = build_report('192.0.2.9/32', 0, [shared], [dict(shared)])
        changed = next(t for t in report['transitions']
                       if t['before_rule'] == 'same' and t['after_rule'] == 'same')
        self.assertEqual(changed['before_action'], 'allow')
        self.assertEqual(changed['after_action'], 'allow')
        self.assertEqual(changed['packets'], 2 ** 32)
        # The identical-id, identical-semantics pair is retained even though
        # nothing changed; the rest of the domain stays default-to-default.
        self.assertTrue(any(t['before_rule'] is None and t['after_rule'] is None
                            for t in report['transitions']))


class ValidationTests(unittest.TestCase):
    def good(self, **over):
        item = rule('r', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 81), 'allow')
        item.update(over)
        return item

    def test_rule_validation_failures(self):
        bad = [
            self.good(id=''),
            self.good(id=' x '),
            self.good(id='x\0y'),
            self.good(src='10.0.0.0/33'),
            self.good(src='10.0.0.1/24'),
            self.good(src='::1/128'),
            self.good(src=10),
            self.good(src=None),
            self.good(dst='2001:db8::/32'),
            self.good(dst='10/8'),
            self.good(protocol='icmp'),
            self.good(protocol='TCP'),
            self.good(action='permit'),
            self.good(action=None),
            self.good(ports=(80, 81)),
            self.good(ports=[80]),
            self.good(ports=[80, 81, 82]),
            self.good(ports=[True, False]),
            self.good(ports=[1.0, 2]),
            self.good(ports=[-1, 80]),
            self.good(ports=[81, 80]),
            self.good(ports=[0, 65536]),
            dict(self.good(), extra=1),
            {'id': 'r', 'src': '0.0.0.0/0', 'dst': '0.0.0.0/0',
             'protocol': 'tcp', 'ports': [80, 81]},
        ]
        for item in bad:
            with self.subTest(item=str(item)[:60]):
                with self.assertRaises(ValueError):
                    parse_rules([item])

    def test_top_level_and_limit_checks(self):
        with self.assertRaises(ValueError):
            parse_rules('not-a-list')
        with self.assertRaises(ValueError):
            parse_rules([self.good(id='r%d' % i) for i in range(MAX_RULES + 1)])
        with self.assertRaises(ValueError):
            parse_rules([self.good(), dict(self.good(), id='r')])
        # Duplicate ids are per version; the same id is legal across versions.
        parse_rules([self.good()])
        build_report('192.0.2.9/32', 0, [self.good()], [dict(self.good())])

    def test_cidr_freedom_includes_slash0_and_off_pool(self):
        lo, hi = strict_cidr('0.0.0.0/0')
        self.assertEqual((lo, hi), (0, DST_SPACE - 1))
        lo, hi = strict_cidr('8.8.8.8/32')
        self.assertEqual(lo, hi)

    def test_cli_top_level_shape(self):
        # Only {"before": [...], "after": [...]} is accepted by the CLI.
        for payload in ({}, {'before': []}, {'before': [], 'after': [], 'x': 1}):
            with self.assertRaises(ValueError):
                # Mirror common.require exactly as the admin CLI does.
                from ipv4_leases.common import require
                require(payload, 'before after')


class ScaleTests(unittest.TestCase):
    @staticmethod
    def _aligned_cidr(rnd):
        plen = rnd.choice((0, 8, 16, 20, 24, 28, 30, 31, 32))
        block = 1 << (32 - plen)
        address = rnd.randrange(0, DST_SPACE // block) * block if plen else 0
        return str(ipaddress.IPv4Network((address, plen), strict=False))

    def _policy(self, rnd):
        out = []
        for i in range(MAX_RULES):
            lo = rnd.choice((0, 80, 1024, 65000))
            hi = rnd.choice((lo, 81, 65535))
            if hi < lo:  # keep the closed interval valid
                lo, hi = hi, lo
            out.append(rule('r%02d' % i, self._aligned_cidr(rnd),
                            self._aligned_cidr(rnd),
                            rnd.choice(('tcp', 'udp', 'any')), (lo, hi),
                            rnd.choice(('allow', 'deny'))))
        return out

    def test_64_overlapping_rules_on_slash20_without_enumeration(self):
        rnd = random.Random(9001)
        before, after = self._policy(rnd), self._policy(rnd)
        report = build_report('10.10.0.0/20', 55, before, after)
        self.assertEqual(report['total_packets'], 4094 * DST_SPACE * 2 * PORT_COUNT)
        self.assertEqual(len(report['before']), MAX_RULES + 1)
        self.assertEqual(len(report['after']), MAX_RULES + 1)
        self.assertEqual(sum(t['packets'] for t in report['transitions']),
                         report['total_packets'])
        # Marginals reconcile with per-version effective coverage.
        before_marginal, after_marginal = {}, {}
        for t in report['transitions']:
            before_marginal[t['before_rule']] = (
                before_marginal.get(t['before_rule'], 0) + t['packets'])
            after_marginal[t['after_rule']] = (
                after_marginal.get(t['after_rule'], 0) + t['packets'])
        for rows, marginal in ((report['before'], before_marginal),
                               (report['after'], after_marginal)):
            for row in rows:
                if row['effective_packets']:
                    self.assertEqual(marginal[row['id']], row['effective_packets'])
        # Every witness is a real first-hit packet under an independent scan.
        for t in report['transitions']:
            w = t['witness']
            src = int(ipaddress.IPv4Address(w['src']))
            dst = int(ipaddress.IPv4Address(w['dst']))
            self.assertEqual(
                linear_first_hit(parse_rules(before), src, dst, w['protocol'], w['port']),
                t['before_rule'])
            self.assertEqual(
                linear_first_hit(parse_rules(after), src, dst, w['protocol'], w['port']),
                t['after_rule'])

    def test_nested_prefixes_and_interleaved_ports_complete_fast(self):
        # Adversarial structure: 64 increasingly specific nested prefixes with
        # disjoint interleaved port windows; the reversed second version makes
        # nearly every combination non-empty.  No packet enumeration occurs.
        rules = []
        for i in range(MAX_RULES):
            plen = min(32, i)
            block = 1 << (32 - plen)
            # Align the network address for each prefix length (strict CIDR).
            network = (0x0A000000 // block) * block
            prefix = str(ipaddress.IPv4Network((network, plen), strict=False))
            rules.append(rule(
                'n%02d' % i, '0.0.0.0/0', prefix, 'any',
                (i * 1000, min(65535, i * 1000 + 999)),
                'allow' if i % 2 else 'deny'))
        report = build_report('10.10.0.0/20', 4, rules, list(reversed(rules)))
        self.assertEqual(sum(t['packets'] for t in report['transitions']),
                         report['total_packets'])
        for version in (report['before'], report['after']):
            self.assertEqual(sum(r['effective_packets'] for r in version),
                             report['total_packets'])
            for row in version:
                self.assertEqual(row['raw_packets'],
                                 row['effective_packets'] + row['shadowed_packets'])


class ReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'pool.sqlite'
        self.pool = Pool(self.path)
        self.pool.initialize(POOL_CIDR)
        self.pool.enable_history()

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def _snapshot(self):
        raw = sqlite3.connect(self.path)
        data = {
            'meta': raw.execute('SELECT * FROM metadata').fetchall(),
            'leases': raw.execute('SELECT * FROM leases ORDER BY address').fetchall(),
            'events': raw.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall(),
            'changes': raw.execute('SELECT * FROM history_changes ORDER BY seq,address').fetchall(),
        }
        try:
            data['external'] = raw.execute(
                'SELECT * FROM external_dhcp_claims ORDER BY address').fetchall()
        except sqlite3.OperationalError:
            data['external'] = None
        raw.close()
        return data

    def _seed_facts(self):
        # Expired leases, a live lease and active/expired external claims.
        self.pool.operate('acquire', 0, 'A', 5)
        self.pool.operate('acquire', 0, 'B', 50)
        self.pool.db.execute(
            'CREATE TABLE IF NOT EXISTS external_dhcp_claims ('
            'server INTEGER NOT NULL, mac TEXT NOT NULL, address INTEGER NOT NULL, '
            'observed_at INTEGER NOT NULL, ttl INTEGER NOT NULL, expires INTEGER NOT NULL, '
            'PRIMARY KEY(server,mac,address,observed_at,ttl))')
        self.pool.db.execute(
            'INSERT INTO external_dhcp_claims VALUES(1,"aa:bb",3221225993,0,2,2)')
        self.pool.db.execute(
            'INSERT INTO external_dhcp_claims VALUES(1,"aa:cc",3221225994,0,99,99)')
        self.pool.db.commit()

    def test_success_invalid_and_injected_failure_change_nothing(self):
        self._seed_facts()
        good_before = [rule('b', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 81), 'allow')]
        good_after = [rule('a', '0.0.0.0/0', '0.0.0.0/0', 'udp', (53, 53), 'deny')]
        before = self._snapshot()
        report = self.pool.acl_diff(good_before, good_after)
        self.assertEqual(report['clock'], 0)
        self.assertEqual(self._snapshot(), before)
        # Invalid input must roll back without touching the database.
        with self.assertRaises(ValueError):
            self.pool.acl_diff([dict(good_before[0], ports=(1, 2))], good_after)
        self.assertEqual(self._snapshot(), before)
        # An injected compute failure likewise leaves every fact untouched.
        from ipv4_leases import acl as acl_module
        original = acl_module.first_hit_partition

        def boom(*_args, **_kwargs):
            raise RuntimeError('injected compute failure')
        acl_module.first_hit_partition = boom
        try:
            with self.assertRaises(RuntimeError):
                self.pool.acl_diff(good_before, good_after)
        finally:
            acl_module.first_hit_partition = original
        self.assertEqual(self._snapshot(), before)

    def test_legacy_pool_without_history_tables(self):
        for name in ('history_changes', 'history_events', 'history_meta'):
            self.pool.db.execute('DROP TABLE %s' % name)
        self.pool.db.commit()
        report = self.pool.acl_diff([], [])
        self.assertEqual(report['total_packets'],
                         len(POOL_HOSTS) * DST_SPACE * 2 * PORT_COUNT)
        raw = sqlite3.connect(self.path)
        tables = {row[0] for row in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        raw.close()
        self.assertFalse(any(name.startswith('history') for name in tables))

    def test_interleaved_readers_share_one_committed_snapshot(self):
        import concurrent.futures

        def reader(_):
            reader_pool = Pool(self.path)
            try:
                report = reader_pool.acl_diff([], [])
                self.assertEqual(report['cidr'], POOL_CIDR)
                return report['clock']
            finally:
                reader_pool.close()

        for tick in range(5):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                clocks = list(executor.map(reader, range(4)))
            self.pool.operate('list', 100 + tick)
            self.assertTrue(all(clock <= 100 + tick for clock in clocks))

    def test_uninitialized_pool_rejected(self):
        missing = Path(self.tmp.name) / 'missing.sqlite'
        pool = Pool(missing)
        try:
            with self.assertRaises(ValueError):
                pool.acl_diff([], [])
        finally:
            pool.close()
        # The read-only failure never initializes metadata; the file left by
        # the connection constructor stays empty and carries no pool schema.
        raw = sqlite3.connect(missing)
        self.assertEqual(
            raw.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [])
        raw.close()


class AclDiffCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / 'pool.sqlite'
        pool = Pool(self.db)
        pool.initialize('192.0.2.9/32')
        pool.close()
        self.source = Path(self.tmp.name) / 'acl.json'
        self.output = Path(self.tmp.name) / 'report.json'
        self.payload = {
            'before': [rule('B', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (80, 81), 'allow')],
            'after': [
                rule('D', '0.0.0.0/0', '0.0.0.0/1', 'tcp', (81, 81), 'deny'),
                rule('A', '0.0.0.0/0', '0.0.0.0/0', 'tcp', (81, 82), 'allow')]}
        self.source.write_text(json.dumps(self.payload))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, source=None, output=None, db=None):
        return subprocess.run(
            [sys.executable, '-m', 'ipv4_leases.admin', '--db', str(db or self.db),
             'acl-diff', '--source', str(source or self.source),
             '--output', str(output or self.output)],
            capture_output=True, text=True)

    def test_full_round_trip_matches_api_and_file(self):
        done = self.run_cli()
        self.assertEqual(done.returncode, 0, done.stderr)
        printed = json.loads(done.stdout)
        saved = json.loads(self.output.read_text())
        self.assertEqual(printed, saved)
        api = build_report('192.0.2.9/32', 0,
                           self.payload['before'], self.payload['after'])
        api['source_sha256'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.assertEqual(printed, api)
        self.assertEqual(printed['source_sha256'],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(set(printed), {
            'cidr', 'clock', 'total_packets', 'newly_allowed', 'newly_denied',
            'before', 'after', 'transitions', 'source_sha256'})

    def test_error_preserves_existing_report(self):
        self.assertEqual(self.run_cli().returncode, 0)
        previous = self.output.read_text()
        self.source.write_text('{"before":[],"after":[],"x":1}')
        done = self.run_cli()
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, '')
        self.assertIn('fields', done.stderr)
        self.assertEqual(self.output.read_text(), previous)

    def test_duplicate_keys_nonfinite_and_size_limit(self):
        dup = Path(self.tmp.name) / 'dup.json'
        dup.write_text('{"before":[],"before":[],"after":[]}')
        done = self.run_cli(source=dup)
        self.assertEqual(done.returncode, 2)
        self.assertIn('duplicate JSON key', done.stderr)
        nonfinite = Path(self.tmp.name) / 'nf.json'
        nonfinite.write_text('{"before":[{"id":"r","src":"0.0.0.0/0","dst":"0.0.0.0/0",'
                             '"protocol":"tcp","ports":[0,1e999],"action":"allow"}],"after":[]}')
        done = self.run_cli(source=nonfinite)
        self.assertEqual(done.returncode, 2)
        big = Path(self.tmp.name) / 'big.json'
        big.write_bytes(b'{"before":[],"after":[]' + b' ' * 8_000_000)
        done = self.run_cli(source=big)
        self.assertEqual(done.returncode, 2)
        self.assertIn('8 MB', done.stderr)

    def test_path_conflicts_and_symlinks(self):
        for source, output in ((self.source, self.source),
                               (self.source, self.db),
                               (self.db, self.output)):
            done = self.run_cli(source=source, output=output)
            self.assertEqual(done.returncode, 2, done.stderr)
        link = Path(self.tmp.name) / 'link.json'
        link.symlink_to(self.output)
        self.assertEqual(self.run_cli(output=link).returncode, 2)
        source_link = Path(self.tmp.name) / 'slink.json'
        source_link.symlink_to(self.source)
        self.assertEqual(self.run_cli(source=source_link).returncode, 2)
        db_link = Path(self.tmp.name) / 'dblink.sqlite'
        db_link.symlink_to(self.db)
        done = self.run_cli(db=db_link)
        self.assertEqual(done.returncode, 2)
        self.assertIn('symlink', done.stderr)

    def test_missing_and_uninitialized_database(self):
        missing = Path(self.tmp.name) / 'missing.sqlite'
        done = self.run_cli(db=missing)
        self.assertEqual(done.returncode, 2)
        self.assertFalse(missing.exists())
        empty = Path(self.tmp.name) / 'empty.sqlite'
        empty.write_bytes(b'')
        done = self.run_cli(db=empty)
        self.assertEqual(done.returncode, 2)
        self.assertIn('initialize', done.stderr)


if __name__ == '__main__':
    unittest.main()
