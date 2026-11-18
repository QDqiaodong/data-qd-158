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

from ipv4_leases.pool import Pool
from ipv4_leases.routing import (
    MAX_ROUTES, MAX_SCENARIOS, RouteEngine, parse_routes, parse_scenarios,
    build_report,
)


def route(rid, prefix, metric=0, via=None, interface=None):
    return {'id': rid, 'prefix': prefix, 'metric': metric,
            'via': via, 'interface': interface}


def direct(rid, prefix, interface, metric=0):
    return route(rid, prefix, metric=metric, interface=interface)


def gateway(rid, prefix, via, metric=0):
    return route(rid, prefix, metric=metric, via=via)


def scenario(sid, down):
    return {'id': sid, 'down': list(down)}


class Acceptance(unittest.TestCase):
    """The two contract acceptance examples, verbatim."""

    def test_pure_cycle_loses_both_hosts(self):
        routes = [
            gateway('r1', '192.0.2.0/30', '203.0.113.1'),
            gateway('r2', '203.0.113.1/32', '203.0.113.2'),
            gateway('r3', '203.0.113.2/32', '203.0.113.1'),
            direct('r4', '203.0.113.2/32', 'wanA'),
        ]
        scenarios = [scenario('s1', ['wanA']), scenario('s0', [])]
        with tempfile.TemporaryDirectory() as tmp:
            pool = Pool(Path(tmp) / 'p.sqlite')
            pool.initialize('192.0.2.0/30')
            try:
                report = pool.route_impact(routes, scenarios)
            finally:
                pool.close()
        self.assertEqual(set(report), {'cidr', 'clock', 'baseline', 'scenarios'})
        self.assertEqual(report['cidr'], '192.0.2.0/30')
        self.assertEqual(report['clock'], 0)
        self.assertEqual(report['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.2', 'interfaces': ['wanA']}])
        by_id = {item['id']: item for item in report['scenarios']}
        self.assertEqual(list(by_id), ['s0', 's1'])
        self.assertEqual(by_id['s0'], {'id': 's0', 'changes': [], 'changed_hosts': 0,
                                       'lost_hosts': 0, 'recovered_hosts': 0})
        self.assertEqual(by_id['s1'], {
            'id': 's1',
            'changes': [{'start': '192.0.2.1', 'end': '192.0.2.2',
                         'before': ['wanA'], 'after': []}],
            'changed_hosts': 2, 'lost_hosts': 2, 'recovered_hosts': 0})

    def test_off_pool_fallback_to_shorter_prefix(self):
        routes = [
            gateway('r1', '192.0.2.0/30', '203.0.113.1'),
            direct('r2', '203.0.113.0/24', 'wanB'),
            direct('r3', '203.0.113.1/32', 'wanA'),
        ]
        report = build_report('192.0.2.0/30', 7, routes, [scenario('s1', ['wanA'])])
        self.assertEqual(report['clock'], 7)
        self.assertEqual(report['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.2', 'interfaces': ['wanA']}])
        self.assertEqual(report['scenarios'][0], {
            'id': 's1',
            'changes': [{'start': '192.0.2.1', 'end': '192.0.2.2',
                         'before': ['wanA'], 'after': ['wanB']}],
            'changed_hosts': 2, 'lost_hosts': 0, 'recovered_hosts': 0})


class ReferenceModel:
    """Independent brute-force least-fixed-point model on a tiny universe.

    It shares no code with the production engine: selection uses a linear
    longest-prefix scan and the interface equations are solved by naive
    monotone set iteration from the empty set.
    """

    def __init__(self, routes):
        self.routes = routes

    def chosen(self, address):
        best_len, best_metric, winners = -1, None, []
        for _id, network, prefixlen, metric, via, interface in self.routes:
            if network <= address <= network + (1 << (32 - prefixlen)) - 1:
                if prefixlen > best_len:
                    best_len, best_metric, winners = prefixlen, metric, [
                        (via, interface)]
                elif prefixlen == best_len:
                    if metric < best_metric:
                        best_metric, winners = metric, [(via, interface)]
                    elif metric == best_metric:
                        winners.append((via, interface))
        return winners if best_len >= 0 else None

    def labels(self, roots, universe):
        values = {address: frozenset() for address in universe}
        while True:
            changed = False
            for address in universe:
                chosen = self.chosen(address)
                updated = set()
                if chosen is not None:
                    for via, interface in chosen:
                        if interface is not None:
                            updated.add(interface)
                        else:
                            updated |= values[via]
                updated = frozenset(updated)
                if updated != values[address]:
                    values[address] = updated
                    changed = True
            if not changed:
                return {address: sorted(values[address]) for address in roots}


class FuzzCrossCheck(unittest.TestCase):
    """Random small facts: production engine vs. the naive fixed point."""

    def test_random_facts_match_reference(self):
        rnd = random.Random(20261118)
        for trial in range(300):
            with self.subTest(trial=trial):
                pool_net = ipaddress.ip_network('192.0.2.0/29')
                hosts = list(range(int(pool_net.network_address) + 1,
                                   int(pool_net.broadcast_address)))
                raw, used_ids = [], set()
                for _ in range(rnd.randint(0, 14)):
                    rid = 'r%d' % rnd.randrange(1000)
                    if rid in used_ids:
                        continue
                    used_ids.add(rid)
                    if rnd.random() < 0.5:
                        prefix = rnd.choice(['192.0.2.0/29', '192.0.2.0/30',
                                             '192.0.2.1/32', '0.0.0.0/0',
                                             '198.18.0.0/16'])
                    else:
                        octet = rnd.randrange(2, 5)
                        prefix = '10.0.%d.0/24' % octet
                    if rnd.random() < 0.5:
                        raw.append(direct(rid, prefix, 'wan%d' % rnd.randrange(4),
                                          metric=rnd.randrange(3)))
                    else:
                        gateway_ip = '10.0.%d.%d' % (rnd.randrange(2, 5),
                                                     rnd.randrange(1, 8))
                        raw.append(gateway(rid, prefix, gateway_ip,
                                           metric=rnd.randrange(3)))
                parsed, interfaces = parse_routes(raw)
                downs = rnd.sample(sorted(interfaces),
                                   rnd.randrange(len(interfaces) + 1))
                scenarios = [scenario('s', downs)]
                report = build_report(str(pool_net), 0, raw, scenarios)

                universe = set(hosts)
                for _id, network, prefixlen, metric, via, interface in parsed:
                    if via is not None:
                        universe.add(via)

                reference = ReferenceModel(parsed)
                expected_before = reference.labels(hosts, universe)
                surviving = [item for item in parsed
                             if item[5] is None or item[5] not in set(downs)]
                expected_after = ReferenceModel(surviving).labels(hosts, universe)
                got_before = {int(ipaddress.IPv4Address(item['start'])): item
                              for item in report['baseline']}
                for address in hosts:
                    segment = next(item for item in report['baseline']
                                   if int(ipaddress.IPv4Address(item['start'])) <= address
                                   <= int(ipaddress.IPv4Address(item['end'])))
                    self.assertEqual(segment['interfaces'], expected_before[address])
                    change = next((c for c in report['scenarios'][0]['changes']
                                   if int(ipaddress.IPv4Address(c['start'])) <= address
                                   <= int(ipaddress.IPv4Address(c['end']))), None)
                    if expected_before[address] == expected_after[address]:
                        self.assertIsNone(change)
                    else:
                        self.assertEqual(change['before'], expected_before[address])
                        self.assertEqual(change['after'], expected_after[address])

    def test_permutation_invariance(self):
        rnd = random.Random(99)
        routes = [
            gateway('pool', '192.0.2.0/30', '203.0.113.1'),
            gateway('g1', '203.0.113.1/32', '203.0.113.2'),
            gateway('g2', '203.0.113.2/32', '203.0.113.1'),
            direct('g3', '203.0.113.2/32', 'wanA'),
            direct('g4', '203.0.113.1/32', 'wanB'),
        ]
        scenarios = [scenario('z', ['wanA']), scenario('a', ['wanB']),
                     scenario('m', ['wanA', 'wanB']), scenario('e', [])]
        canonical = build_report('192.0.2.0/30', 0, routes, scenarios)
        for _ in range(25):
            rr = routes[:]
            rnd.shuffle(rr)
            ss = scenarios[:]
            rnd.shuffle(ss)
            for item in ss:
                rnd.shuffle(item['down'])
            self.assertEqual(build_report('192.0.2.0/30', 0, rr, ss), canonical)


class BusinessCases(unittest.TestCase):
    def test_ecmp_multiple_exits_union_without_weight(self):
        routes = [
            gateway('p', '192.0.2.0/30', '10.0.0.1'),
            direct('a', '10.0.0.1/32', 'wanZ'),
            direct('b', '10.0.0.1/32', 'wanA'),
            direct('c', '10.0.0.1/32', 'wanM'),
        ]
        report = build_report('192.0.2.0/30', 0, routes, [])
        self.assertEqual(report['baseline'][0]['interfaces'],
                         ['wanA', 'wanM', 'wanZ'])

    def test_metrics_on_same_prefix(self):
        routes = [direct('lo', '192.0.2.0/30', 'wanLow', metric=1),
                  direct('hi', '192.0.2.0/30', 'wanHigh', metric=2)]
        report = build_report('192.0.2.0/30', 0, routes,
                              [scenario('s', ['wanLow'])])
        self.assertEqual(report['baseline'][0]['interfaces'], ['wanLow'])
        self.assertEqual(report['scenarios'][0]['changes'][0]['after'], ['wanHigh'])

    def test_unreachable_best_metric_never_falls_back(self):
        routes = [
            gateway('v', '192.0.2.0/30', '10.0.0.1', metric=1),
            gateway('c1', '10.0.0.1/32', '10.0.0.2'),
            gateway('c2', '10.0.0.2/32', '10.0.0.1'),
            direct('d', '192.0.2.0/30', 'wanD', metric=9),
        ]
        report = build_report('192.0.2.0/30', 0, routes, [])
        self.assertEqual(report['baseline'][0]['interfaces'], [])

    def test_pure_cycle_is_empty(self):
        routes = [
            gateway('p', '192.0.2.0/30', '10.0.0.1'),
            gateway('a', '10.0.0.1/32', '10.0.0.2'),
            gateway('b', '10.0.0.2/32', '10.0.0.3'),
            gateway('c', '10.0.0.3/32', '10.0.0.1'),
        ]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'][0]['interfaces'], [])

    def test_cycle_with_exit_propagates_all_exits(self):
        routes = [
            gateway('p', '192.0.2.0/30', '10.0.0.1'),
            gateway('a', '10.0.0.1/32', '10.0.0.2'),
            gateway('b', '10.0.0.2/32', '10.0.0.1'),
            direct('e1', '10.0.0.2/32', 'wanE'),
            direct('e2', '10.0.0.1/32', 'wanF'),
        ]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'][0]['interfaces'], ['wanE', 'wanF'])

    def test_one_cyclic_branch_does_not_lose_other_exits(self):
        # ECMP at the gateway: one via branch is a pure cycle, one direct exit.
        routes = [
            gateway('p', '192.0.2.0/30', '10.0.0.1'),
            gateway('cyc1', '10.0.0.1/32', '10.0.0.2'),
            gateway('cyc2', '10.0.0.2/32', '10.0.0.1'),
            direct('out', '10.0.0.1/32', 'wanOut'),
        ]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'][0]['interfaces'], ['wanOut'])

    def test_multi_layer_gateways(self):
        routes = [
            gateway('p', '192.0.2.0/30', '10.0.0.1'),
            gateway('l1', '10.0.0.1/32', '10.0.0.2'),
            gateway('l2', '10.0.0.2/32', '10.0.0.3'),
            gateway('l3', '10.0.0.3/32', '10.0.0.4'),
            direct('e', '10.0.0.4/32', 'wanDeep'),
        ]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'][0]['interfaces'], ['wanDeep'])

    def test_self_referential_gateway_is_empty(self):
        routes = [gateway('p', '192.0.2.0/30', '10.0.0.1'),
                  gateway('self', '10.0.0.1/32', '10.0.0.1')]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'][0]['interfaces'], [])

    def test_gateway_inside_pool_resolves_recursively(self):
        routes = [gateway('p', '192.0.2.0/30', '192.0.2.1'),
                  direct('d', '192.0.2.1/32', 'wanPool')]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.2', 'interfaces': ['wanPool']}])

    def test_route_prefixes_escape_pool_slash20_floor(self):
        report = build_report('192.0.2.0/30', 0,
                              [direct('big', '192.0.0.0/16', 'w16')], [])
        self.assertEqual(report['baseline'][0]['interfaces'], ['w16'])
        report = build_report('192.0.2.0/30', 0,
                              [direct('big', '1.0.0.0/8', 'w8')], [])
        self.assertEqual(report['baseline'][0]['interfaces'], [])

    def test_metric_boundary_and_float_rejection(self):
        parse_routes([direct('x', '0.0.0.0/0', 'w', metric=10 ** 9)])
        for metric in (1.0, 1e9):
            with self.assertRaises(ValueError):
                parse_routes([dict(direct('x', '0.0.0.0/0', 'w'),
                                   metric=metric)])

    def test_default_route_and_no_match(self):
        with_default = build_report('192.0.2.0/30', 0,
                                    [direct('d', '0.0.0.0/0', 'wanD')], [])
        self.assertEqual(with_default['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.2', 'interfaces': ['wanD']}])
        no_match = build_report('192.0.2.0/30', 0, [], [])
        self.assertEqual(no_match['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.2', 'interfaces': []}])

    def test_empty_arrays_are_legal(self):
        report = build_report('192.0.2.0/30', 3, [], [])
        self.assertEqual(report['scenarios'], [])
        self.assertEqual(report['clock'], 3)

    def test_interface_names_python_string_order(self):
        routes = [gateway('p', '192.0.2.0/30', '10.0.0.1'),
                  direct('a', '10.0.0.1/32', 'zzz'),
                  direct('b', '10.0.0.1/32', 'aaa'),
                  direct('c', '10.0.0.1/32', 'AAA')]
        self.assertEqual(build_report('192.0.2.0/30', 0, routes, [])
                         ['baseline'][0]['interfaces'], ['AAA', 'aaa', 'zzz'])

    def test_adjacent_equal_segments_merge_across_prefix_bounds(self):
        # Hosts .1..6 are governed by different prefixes but resolve equal:
        routes = [direct('d', '0.0.0.0/0', 'wan'),
                  direct('m', '192.0.2.0/29', 'wan'),
                  direct('h', '192.0.2.3/32', 'wan')]
        report = build_report('192.0.2.0/29', 0, routes, [])
        self.assertEqual(report['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.6', 'interfaces': ['wan']}])

    def test_different_sets_split_intervals_and_counts_sum(self):
        routes = [direct('h1', '192.0.2.1/32', 'wanA'),
                  direct('h2', '192.0.2.2/32', 'wanB'),
                  direct('h3', '192.0.2.3/32', 'wanB'),
                  gateway('rest', '192.0.2.0/29', '10.9.9.9')]
        report = build_report('192.0.2.0/29', 0, routes,
                              [scenario('s', ['wanA', 'wanB'])])
        self.assertEqual([(b['start'], b['end'], b['interfaces'])
                          for b in report['baseline']], [
            ('192.0.2.1', '192.0.2.1', ['wanA']),
            ('192.0.2.2', '192.0.2.3', ['wanB']),
            ('192.0.2.4', '192.0.2.6', [])])
        sc = report['scenarios'][0]
        # .1..3 lose their egress; .4..6 were already empty and stay empty.
        self.assertEqual(sc['changed_hosts'], 3)
        self.assertEqual(sc['lost_hosts'], 3)
        self.assertEqual(sc['recovered_hosts'], 0)
        self.assertEqual(sum(
            int(ipaddress.IPv4Address(c['end']))
            - int(ipaddress.IPv4Address(c['start'])) + 1
            for c in sc['changes']), 3)

    def test_slash31_and_slash32_pools(self):
        report = build_report('192.0.2.0/31', 0,
                              [direct('d', '0.0.0.0/0', 'w')], [])
        self.assertEqual(report['baseline'], [
            {'start': '192.0.2.0', 'end': '192.0.2.1', 'interfaces': ['w']}])
        report = build_report('192.0.2.8/32', 0,
                              [direct('d', '192.0.2.8/32', 'w')], [])
        self.assertEqual(report['baseline'], [
            {'start': '192.0.2.8', 'end': '192.0.2.8', 'interfaces': ['w']}])

    def test_withdrawn_off_pool_specific_route_falls_back(self):
        routes = [
            gateway('p', '192.0.2.0/30', '203.0.113.1'),
            direct('lo', '203.0.113.0/24', 'wanB'),
            direct('hi', '203.0.113.1/32', 'wanA'),
        ]
        report = build_report('192.0.2.0/30', 0, routes,
                              [scenario('s', ['wanA'])])
        self.assertEqual(report['scenarios'][0]['changes'][0]['after'], ['wanB'])

    def test_withdrawn_best_direct_enables_worse_metric(self):
        routes = [direct('best', '192.0.2.0/30', 'wanBest', metric=1),
                  direct('worse', '192.0.2.0/30', 'wanWorse', metric=5)]
        report = build_report('192.0.2.0/30', 0, routes,
                              [scenario('s', ['wanBest'])])
        self.assertEqual(report['scenarios'][0]['changes'][0]['after'],
                         ['wanWorse'])

    def test_gateway_routes_are_never_withdrawn(self):
        # A down interface never removes via routes even when named identically.
        routes = [gateway('p', '192.0.2.0/30', '10.0.0.1'),
                  direct('g', '10.0.0.1/32', 'wanA')]
        report = build_report('192.0.2.0/30', 0, routes,
                              [scenario('s', ['wanA'])])
        # The gateway route remains; only the direct egress disappeared.
        self.assertEqual(report['scenarios'][0]['changes'][0]['after'], [])

    def test_recovered_accounting_branch(self):
        # Empty baseline via a more-specific direct route whose interface is
        # downed, revealing a reachable shorter-prefix direct route.
        routes = [
            direct('shadow', '192.0.2.1/32', 'dead'),
            direct('base', '192.0.2.0/30', 'wanG'),
        ]
        report = build_report('192.0.2.0/30', 0, routes,
                              [scenario('s', ['dead'])])
        sc = report['scenarios'][0]
        self.assertEqual(sc['changed_hosts'], 1)
        self.assertEqual(sc['lost_hosts'], 0)
        # before is non-empty here; this still exercises change accounting;
        # recovered (empty->non-empty) is structurally unreachable under
        # withdraw-only faults and stays zero in every acceptance case.
        self.assertEqual(sc['recovered_hosts'], 0)


class ValidationTests(unittest.TestCase):
    def _interfaces(self):
        _routes, interfaces = parse_routes([direct('a', '10.0.0.0/8', 'wanA')])
        return interfaces

    def test_route_validation_failures(self):
        good = direct('a', '10.0.0.0/8', 'wanA')
        good_gw = gateway('a', '10.0.0.0/8', '10.0.0.1')
        bad = [
            [dict(good, id=True)],
            [dict(good, id='')],
            [direct('a', '10.0.0.0/8', 'x'), direct('a', '10.1.0.0/16', 'y')],
            [dict(good, prefix='192.0.2.1/24')],
            [dict(good, prefix='::1/128')],
            [dict(good, prefix='10.0.0.0/33')],
            [dict(good, prefix=10)],
            [dict(good, metric=True)],
            [dict(good, metric=10 ** 9 + 1)],
            [dict(good, metric=-1)],
            [dict(good_gw, via='10.0.0.01')],
            [dict(good_gw, via='::1')],
            [dict(good_gw, via=5)],
            [dict(good, extra=1)],
            [dict(good, via='10.0.0.1', interface='x')],
            [{'id': 'x', 'prefix': '10.0.0.0/8', 'metric': 0,
              'via': None, 'interface': None}],
            [dict(good, interface='')],
            [dict(good, interface=' a ')],
            [dict(good, interface='x\ny')],
            [{'id': 'x', 'prefix': '10/8', 'metric': 0,
              'via': None, 'interface': 'a'}],
            'not-a-list',
        ]
        for item in bad:
            with self.subTest(item=str(item)[:60]):
                with self.assertRaises(ValueError):
                    parse_routes(item)

    def test_route_limits_and_prefix_freedom(self):
        with self.assertRaises(ValueError):
            parse_routes([direct('r%d' % i, '10.0.0.0/8', 'w')
                          for i in range(MAX_ROUTES + 1)])
        parsed, _ = parse_routes([
            direct('zero', '0.0.0.0/0', 'w'),
            direct('big', '224.0.0.0/4', 'w2'),
            direct('host', '198.51.100.7/32', 'w3'),
        ])
        self.assertEqual(len(parsed), 3)

    def test_scenario_validation_failures(self):
        interfaces = self._interfaces()
        bad = [
            scenario('a', ['nope']),
            scenario('a', ['wanA', 'wanA']),
            scenario('a', [None]),
            scenario('a', [5]),
            scenario('a', ['']),
            dict(scenario('a', []), extra=1),
            dict(scenario('a', []), id=''),
            scenario('a', 'not-a-list'),
        ]
        for item in bad:
            with self.subTest(item=str(item)[:60]):
                with self.assertRaises(ValueError):
                    parse_scenarios([item], interfaces)
        with self.assertRaises(ValueError):
            parse_scenarios([scenario('s%d' % i, [])
                             for i in range(MAX_SCENARIOS + 1)], interfaces)
        with self.assertRaises(ValueError):
            parse_scenarios([scenario('a', ['wanA'] * 2049)], interfaces)
        parse_scenarios([scenario('a', ['wanA'])], interfaces)

    def test_down_limit_boundary_and_non_dict_items(self):
        interfaces = {'w%d' % i for i in range(2048)}
        parse_scenarios([scenario('s', sorted(interfaces))], interfaces)
        for bad in ([42], [None], [['x']]):
            with self.assertRaises(ValueError):
                parse_routes(bad)

    def test_duplicate_scenario_id_and_cross_class_identifier(self):
        interfaces = self._interfaces()
        with self.assertRaises(ValueError):
            parse_scenarios([scenario('shared', []), scenario('shared', [])],
                            interfaces)
        # The same identifier may be used by one route and one scenario.
        parse_scenarios([scenario('a', [])], interfaces)

    def test_top_level_shape_enforced_by_contract_reader(self):
        # The CLI requires exactly routes/scenarios; the API takes two arrays.
        with self.assertRaises(ValueError):
            build_report('192.0.2.0/30', 0, {}, [])
        with self.assertRaises(ValueError):
            build_report('192.0.2.0/30', 0, [], {})


class ScaleTests(unittest.TestCase):
    @staticmethod
    def _addr(number):
        return str(ipaddress.IPv4Address(0x0B000000 + number))

    def test_1500_layer_gateway_chain(self):
        depth = 1500
        routes = [gateway('pool', '192.0.2.0/30', self._addr(1))]
        for i in range(1, depth):
            routes.append(gateway('h%d' % i, '%s/32' % self._addr(i),
                                   self._addr(i + 1)))
        routes.append(direct('hend', '%s/32' % self._addr(depth), 'wanFar'))
        report = build_report('192.0.2.0/30', 0, routes, [])
        self.assertEqual(report['baseline'][0]['interfaces'], ['wanFar'])
        broken = routes[:-1] + [direct('hend', '%s/32' % self._addr(depth),
                                       'wanFar2')]
        report = build_report('192.0.2.0/30', 0, broken,
                              [scenario('s', ['wanFar2'])])
        self.assertEqual(report['scenarios'][0]['lost_hosts'], 2)

    def test_fork_join_and_multi_exit_cycle(self):
        routes = [
            gateway('pool', '192.0.2.0/30', '12.0.0.1'),
            gateway('g1', '12.0.0.1/32', '12.0.0.2'),
            gateway('g2', '12.0.0.1/32', '12.0.0.3'),
            gateway('a1', '12.0.0.2/32', '12.0.0.4'),
            gateway('a2', '12.0.0.4/32', '12.0.0.2'),
            direct('a3', '12.0.0.4/32', 'wanE'),
            direct('b', '12.0.0.3/32', 'wanF'),
            gateway('j1', '12.0.0.2/32', '12.0.0.9'),
            gateway('j2', '12.0.0.3/32', '12.0.0.9'),
            direct('j', '12.0.0.9/32', 'wanG'),
        ]
        report = build_report('192.0.2.0/30', 0, routes, [])
        self.assertEqual(report['baseline'][0]['interfaces'],
                         ['wanE', 'wanF', 'wanG'])
        report = build_report('192.0.2.0/30', 0, routes,
                              [scenario('s', ['wanF'])])
        self.assertEqual(report['scenarios'][0]['changes'][0]['after'],
                         ['wanE', 'wanG'])

    def test_2048_routes_and_32_scenarios_on_maximum_pool(self):
        routes = []
        for i in range(MAX_ROUTES):
            routes.append(direct('r%d' % i, '192.168.%d.%d/32'
                                 % (i // 256, i % 256), 'wan%d' % (i % 16)))
        scenarios = [scenario('sc%02d' % i, ['wan%d' % (i % 16)])
                     for i in range(MAX_SCENARIOS)]
        report = build_report('10.10.0.0/20', 0, routes, scenarios)
        self.assertEqual(len(report['scenarios']), MAX_SCENARIOS)
        self.assertEqual([item['id'] for item in report['scenarios']],
                         sorted(item['id'] for item in scenarios))
        # Every downed interface removes some /32 directs; some hosts keep
        # their default (no route) empty set.
        for item in report['scenarios']:
            self.assertEqual(item['changed_hosts'], item['lost_hosts'])
            self.assertEqual(item['recovered_hosts'], 0)


class ReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'pool.sqlite'
        self.pool = Pool(self.path)
        self.pool.initialize('192.0.2.0/29')
        self.pool.enable_history()

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def _raw_snapshot(self):
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

    def test_analysis_never_writes_even_with_expired_facts(self):
        self.pool.operate('acquire', 0, 'A', 5)
        self.pool.operate('acquire', 0, 'B', 5)
        self.pool.db.execute(
            'CREATE TABLE IF NOT EXISTS external_dhcp_claims ('
            'server INTEGER NOT NULL, mac TEXT NOT NULL, address INTEGER NOT NULL, '
            'observed_at INTEGER NOT NULL, ttl INTEGER NOT NULL, expires INTEGER NOT NULL, '
            'PRIMARY KEY(server,mac,address,observed_at,ttl))')
        self.pool.db.execute(
            'INSERT INTO external_dhcp_claims VALUES(1,"aa:bb",3221225989,0,2,2)')
        self.pool.db.execute(
            'INSERT INTO external_dhcp_claims VALUES(1,"aa:cc",3221225990,0,99,99)')
        self.pool.db.commit()
        before = self._raw_snapshot()
        report = self.pool.route_impact(
            [direct('d', '0.0.0.0/0', 'wanX')], [scenario('s', ['wanX'])])
        self.assertEqual(report['clock'], 0)
        self.assertEqual(self._raw_snapshot(), before)

    def test_legacy_pool_without_history_tables(self):
        for name in ('history_changes', 'history_events', 'history_meta'):
            self.pool.db.execute('DROP TABLE %s' % name)
        self.pool.db.commit()
        report = self.pool.route_impact([], [])
        self.assertEqual(report['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.6', 'interfaces': []}])
        raw = sqlite3.connect(self.path)
        tables = {row[0] for row in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        raw.close()
        self.assertFalse(any(name.startswith('history') for name in tables))

    def test_compute_failure_writes_nothing(self):
        before = self._raw_snapshot()
        with self.assertRaises(ValueError):
            self.pool.route_impact(
                [dict(direct('a', '10.0.0.0/8', 'w'), prefix='bad')], [])
        self.assertEqual(self._raw_snapshot(), before)

    def test_interleaved_reader_uses_one_committed_snapshot(self):
        def reader(_):
            reader_pool = Pool(self.path)
            try:
                report = reader_pool.route_impact(
                    [direct('d', '0.0.0.0/0', 'wan')], [])
                self.assertEqual(report['cidr'], '192.0.2.0/29')
                return report['clock']
            finally:
                reader_pool.close()

        for tick in range(6):
            with concurrent_futures() as executor:
                clocks = list(executor.map(reader, range(4)))
            self.pool.operate('list', 100 + tick)
            self.assertTrue(all(clock <= 100 + tick for clock in clocks))


def concurrent_futures():
    import concurrent.futures
    return concurrent.futures.ThreadPoolExecutor(max_workers=4)


class RouteImpactCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / 'pool.sqlite'
        pool = Pool(self.db)
        pool.initialize('192.0.2.0/30')
        pool.close()
        self.source = Path(self.tmp.name) / 'routes.json'
        self.output = Path(self.tmp.name) / 'report.json'
        self.payload = {'routes': [
            gateway('r1', '192.0.2.0/30', '203.0.113.1'),
            direct('r2', '203.0.113.1/32', 'wanA')],
            'scenarios': [scenario('s1', ['wanA'])]}
        self.source.write_text(json.dumps(self.payload))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *extra):
        return subprocess.run(
            [sys.executable, '-m', 'ipv4_leases.admin', '--db', str(self.db),
             'route-impact', '--source', str(self.source),
             '--output', str(self.output), *extra],
            capture_output=True, text=True)

    def test_full_round_trip(self):
        done = self.run_cli()
        self.assertEqual(done.returncode, 0, done.stderr)
        printed = json.loads(done.stdout)
        saved = json.loads(self.output.read_text())
        self.assertEqual(printed, saved)
        self.assertEqual(printed['source_sha256'],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(set(printed),
                         {'cidr', 'clock', 'baseline', 'scenarios',
                          'source_sha256'})
        self.assertEqual(printed['baseline'], [
            {'start': '192.0.2.1', 'end': '192.0.2.2', 'interfaces': ['wanA']}])

    def test_error_preserves_existing_report(self):
        self.assertEqual(self.run_cli().returncode, 0)
        previous = self.output.read_text()
        self.source.write_text('{"routes":[],"scenarios":[],"x":1}')
        done = self.run_cli()
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, '')
        self.assertIn('fields', done.stderr)
        self.assertEqual(self.output.read_text(), previous)

    def test_path_conflicts_and_symlinks(self):
        for source, output in [(self.source, self.source),
                               (self.source, self.db),
                               (self.db, self.output)]:
            self.source, self.output = source, output
            done = self.run_cli()
            self.assertEqual(done.returncode, 2, done.stderr)
        self.source, self.output = (Path(self.tmp.name) / 'routes.json',
                                    Path(self.tmp.name) / 'report.json')
        link = Path(self.tmp.name) / 'link.json'
        link.symlink_to(self.output)
        self.output = link
        self.assertEqual(self.run_cli().returncode, 2)
        source_link = Path(self.tmp.name) / 'slink.json'
        source_link.symlink_to(self.source)
        self.source, self.output = source_link, Path(self.tmp.name) / 'r2.json'
        self.assertEqual(self.run_cli().returncode, 2)
        db_link = Path(self.tmp.name) / 'dblink.sqlite'
        db_link.symlink_to(self.db)
        done = subprocess.run(
            [sys.executable, '-m', 'ipv4_leases.admin', '--db', str(db_link),
             'route-impact', '--source', str(self.source),
             '--output', str(self.output)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertIn('symlink', done.stderr)

    def test_missing_and_uninitialized_database(self):
        missing = Path(self.tmp.name) / 'missing.sqlite'
        done = subprocess.run(
            [sys.executable, '-m', 'ipv4_leases.admin', '--db', str(missing),
             'route-impact', '--source', str(self.source),
             '--output', str(self.output)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertFalse(missing.exists())
        empty = Path(self.tmp.name) / 'empty.sqlite'
        empty.write_bytes(b'')
        done = subprocess.run(
            [sys.executable, '-m', 'ipv4_leases.admin', '--db', str(empty),
             'route-impact', '--source', str(self.source),
             '--output', str(self.output)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertIn('initialize', done.stderr)

    def test_duplicate_keys_and_size_limit(self):
        dup = Path(self.tmp.name) / 'dup.json'
        dup.write_text('{"routes":[],"routes":[],"scenarios":[]}')
        self.source = dup
        done = self.run_cli()
        self.assertEqual(done.returncode, 2)
        self.assertIn('duplicate JSON key', done.stderr)
        big = Path(self.tmp.name) / 'big.json'
        big.write_bytes(b'{"routes":[],"scenarios":[]' + b' ' * 8_000_000)
        self.source = big
        done = self.run_cli()
        self.assertEqual(done.returncode, 2)
        self.assertIn('8 MB', done.stderr)


if __name__ == '__main__':
    unittest.main()
