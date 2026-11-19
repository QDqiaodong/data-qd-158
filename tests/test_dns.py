import unittest
from ipv4_leases.dns import (DnsError, compile_mirror, normalize_name,
                             ptr_name, validate_config)


def ref_compile(zone, bindings, aliases, active, now):
    """Independent tiny reference compiler, written straight from the spec.

    Shares no code with the production compiler: it rebuilds A RRsets,
    resolves each CNAME owner by walking plain dicts with an explicit stack,
    and emits PTRs independently.  Used only to cross-check small scenarios.
    """
    bound = {c: (n, rev) for c, n, rev in bindings}
    a = {}
    for client, (address, expires) in active.items():
        if client not in bound:
            continue
        name = bound[client][0]
        a.setdefault(name, []).append((address, expires))
    targets = dict(aliases)
    for owner in targets:
        if owner in a:
            raise DnsError('conflict ' + owner)

    def terminal(owner):
        seen = []
        cur = owner
        while cur not in a:
            if cur in seen:
                raise DnsError('cycle ' + cur)
            if cur not in targets:
                raise DnsError('dangle ' + cur)
            seen.append(cur)
            cur = targets[cur]
        return cur

    out = []
    for name in sorted(a):
        vals = sorted('.'.join(str(x) for x in v.to_bytes(4, 'big')) for v, _ in a[name])
        out.append({'name': name, 'type': 'A',
                    'ttl': min(e - now for _, e in a[name]), 'values': vals})
    for owner, target in aliases:
        end = terminal(owner)
        out.append({'name': owner, 'type': 'CNAME',
                    'ttl': min(e - now for _, e in a[end]), 'values': [target]})
    for client, (address, expires) in active.items():
        if client in bound and bound[client][1]:
            octets = address.to_bytes(4, 'big')
            owner = '%d.%d.%d.%d.in-addr.arpa.' % (octets[3], octets[2], octets[1], octets[0])
            out.append({'name': owner, 'type': 'PTR',
                        'ttl': expires - now, 'values': [bound[client][0]]})
    out.sort(key=lambda r: (r['name'], r['type']))
    return out


class NameNormalization(unittest.TestCase):
    def test_case_trailing_dot_and_basic_form(self):
        self.assertEqual(normalize_name('SVC.Lab.Test'), 'svc.lab.test.')
        self.assertEqual(normalize_name('svc.lab.test.'), 'svc.lab.test.')
        self.assertEqual(normalize_name('A'), 'a.')
        self.assertEqual(normalize_name('a.'), 'a.')

    def test_rejected_names(self):
        bad = ['', '.', '..', 'a..b', 'a..', '.a', 'a-.b', '-a.b',
               'a.b-', 'a b.test', 'a_b.test', 'a..test.', 'svc..',
               'a.test..', ' leading.test', 'trailing.test ', 'a.b/c',
               'aé.test', 'x.' + 'a' * 64]
        for name in bad:
            with self.subTest(name=name), self.assertRaises(DnsError):
                normalize_name(name)
        # ASCII-compatible punycode spelling is ordinary ASCII and is allowed;
        # the actual Unicode spelling is what must be rejected.
        self.assertEqual(normalize_name('xn--caf-dma.test.'), 'xn--caf-dma.test.')

    def test_label_and_name_length_bounds_accepted(self):
        self.assertEqual(normalize_name('a' * 63), 'a' * 63 + '.')
        self.assertEqual(normalize_name('a' * 63 + '.' + 'b'), 'a' * 63 + '.b.')
        long_body = '.'.join(['a' * 63] * 4)  # 255 > 253
        with self.assertRaises(DnsError):
            normalize_name(long_body)
        body_253 = 'a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 61
        self.assertEqual(len(body_253), 253)
        self.assertEqual(normalize_name(body_253), body_253 + '.')
        with self.assertRaises(DnsError):
            normalize_name(body_253 + 'e')

    def test_non_string_rejected(self):
        for value in (None, 1, b'a.b', ['a.b']):
            with self.assertRaises(ValueError):
                normalize_name(value)


class ConfigValidation(unittest.TestCase):
    def test_zone_boundary_must_match_full_labels(self):
        zone, bindings, aliases = validate_config(
            'lab.test.', [], [{'name': 'api.lab.test', 'target': 'lab.test'}])
        self.assertEqual(zone, 'lab.test.')
        self.assertEqual(aliases[0], ('api.lab.test.', 'lab.test.'))
        # Suffix look-alikes are outside the zone.
        with self.assertRaises(DnsError):
            validate_config('lab.test',
                            [{'client': 'A', 'name': 'notlab.test', 'reverse': False}], [])
        with self.assertRaises(DnsError):
            validate_config('lab.test', [],
                            [{'name': 'a.notlab.test', 'target': 'lab.test'}])

    def test_apex_alias_rejected_but_apex_binding_allowed(self):
        with self.assertRaises(DnsError):
            validate_config('lab.test', [], [{'name': 'lab.test', 'target': 'x.lab.test'}])
        zone, bindings, _ = validate_config(
            'lab.test', [{'client': 'A', 'name': 'lab.test', 'reverse': False}], [])
        self.assertEqual(bindings, [('A', 'lab.test.', False)])

    def test_duplicate_alias_owner_after_normalization(self):
        with self.assertRaisesRegex(DnsError, 'duplicate alias owner'):
            validate_config('lab.test', [], [
                {'name': 'API.lab.test', 'target': 'svc.lab.test'},
                {'name': 'api.lab.test.', 'target': 'other.lab.test'}])

    def test_duplicate_client_even_identical_binding_rejected(self):
        with self.assertRaisesRegex(DnsError, 'duplicate binding client'):
            validate_config('lab.test', [
                {'client': 'A', 'name': 'svc.lab.test', 'reverse': True},
                {'client': 'A', 'name': 'svc.lab.test', 'reverse': True}], [])

    def test_reverse_must_be_real_bool(self):
        for value in (0, 1, 'true', None):
            with self.assertRaises(DnsError):
                validate_config('lab.test',
                                [{'client': 'A', 'name': 'a.lab.test', 'reverse': value}], [])

    def test_limits_and_empty_arrays(self):
        bindings = [{'client': 'c%d' % i, 'name': 'n%d.lab.test' % i, 'reverse': i % 2 == 0}
                    for i in range(128)]
        zone, got, _ = validate_config('lab.test', bindings, [])
        self.assertEqual(len(got), 128)
        with self.assertRaises(DnsError):
            validate_config('lab.test', bindings + [
                {'client': 'extra', 'name': 'x.lab.test', 'reverse': False}], [])
        aliases = [{'name': 'a%d.lab.test' % i, 'target': 'svc.lab.test'} for i in range(2048)]
        self.assertEqual(len(validate_config('lab.test', [], aliases)[2]), 2048)
        with self.assertRaises(DnsError):
            validate_config('lab.test', [], aliases + [
                {'name': 'toomany.lab.test', 'target': 'svc.lab.test'}])
        self.assertEqual(validate_config('lab.test', [], []), ('lab.test.', [], []))

    def test_strict_fields(self):
        with self.assertRaises(DnsError):
            validate_config('lab.test', [{'client': 'A', 'name': 'a.lab.test'}], [])
        with self.assertRaises(DnsError):
            validate_config('lab.test', [], [{'name': 'a.lab.test'}])


def addr(last):
    return int.from_bytes(bytes((192, 0, 2, last)), 'big')


class MirrorSemantics(unittest.TestCase):
    def setUp(self):
        self.zone = 'lab.test.'
        self.bindings = [('A', 'svc.lab.test.', True), ('B', 'svc.lab.test.', False)]

    def test_multi_value_a_min_ttl_and_ptr(self):
        active = {'A': (addr(1), 8), 'B': (addr(2), 10)}
        records = compile_mirror(self.zone, self.bindings, [], active, 5)
        a = next(r for r in records if r['type'] == 'A')
        self.assertEqual((a['name'], a['ttl'], a['values']),
                         ('svc.lab.test.', 3, ['192.0.2.1', '192.0.2.2']))
        ptr = next(r for r in records if r['type'] == 'PTR')
        self.assertEqual(ptr, {'name': '1.2.0.192.in-addr.arpa.', 'type': 'PTR',
                               'ttl': 3, 'values': ['svc.lab.test.']})
        # B has reverse=false: exactly one PTR.
        self.assertEqual([r['name'] for r in records if r['type'] == 'PTR'],
                         ['1.2.0.192.in-addr.arpa.'])
        self.assertEqual(records, ref_compile(self.zone, self.bindings, [], active, 5))

    def test_ptr_ttl_is_per_address_not_shared_minimum(self):
        active = {'A': (addr(1), 20), 'B': (addr(2), 8)}
        records = compile_mirror(self.zone, self.bindings, [], active, 5)
        a = next(r for r in records if r['type'] == 'A')
        ptr = next(r for r in records if r['type'] == 'PTR')
        self.assertEqual(a['ttl'], 3)          # min(15, 3)
        self.assertEqual(ptr['ttl'], 15)       # A's own remainder

    def test_direct_and_multi_level_cname_share_terminal_ttl(self):
        aliases = [('api.lab.test.', 'svc.lab.test.'),
                   ('edge.lab.test.', 'api.lab.test.')]
        active = {'A': (addr(1), 20)}
        records = compile_mirror(self.zone, self.bindings, aliases, active, 5)
        by_name = {r['name']: r for r in records}
        self.assertEqual(by_name['api.lab.test.'],
                         {'name': 'api.lab.test.', 'type': 'CNAME', 'ttl': 15,
                          'values': ['svc.lab.test.']})
        self.assertEqual(by_name['edge.lab.test.'],
                         {'name': 'edge.lab.test.', 'type': 'CNAME', 'ttl': 15,
                          'values': ['api.lab.test.']})
        self.assertEqual(records, ref_compile(self.zone, self.bindings, aliases, active, 5))

    def test_ttl_change_propagates_to_every_dependent(self):
        aliases = [('api.lab.test.', 'svc.lab.test.'),
                   ('edge.lab.test.', 'api.lab.test.')]
        active = {'A': (addr(1), 20)}
        first = {r['name']: r for r in
                 compile_mirror(self.zone, self.bindings, aliases, active, 5)}
        self.assertEqual([first[n]['ttl'] for n in
                          ('svc.lab.test.', 'api.lab.test.', 'edge.lab.test.')], [15, 15, 15])
        # Shortening then lengthening the sole lease moves every TTL together.
        active = {'A': (addr(1), 12)}
        short = {r['name']: r for r in
                 compile_mirror(self.zone, self.bindings, aliases, active, 5)}
        self.assertEqual([short[n]['ttl'] for n in
                          ('svc.lab.test.', 'api.lab.test.', 'edge.lab.test.')], [7, 7, 7])
        active = {'A': (addr(1), 40)}
        long = {r['name']: r for r in
                compile_mirror(self.zone, self.bindings, aliases, active, 5)}
        self.assertEqual([long[n]['ttl'] for n in
                          ('svc.lab.test.', 'api.lab.test.', 'edge.lab.test.')], [35, 35, 35])

    def test_a_cname_owner_collision(self):
        aliases = [('svc.lab.test.', 'other.lab.test.')]
        with self.assertRaisesRegex(DnsError, 'also has active A'):
            compile_mirror(self.zone, self.bindings, aliases, {'A': (addr(1), 20)}, 5)

    def test_cycle_self_loop_and_long_cycle(self):
        with self.assertRaisesRegex(DnsError, 'cycle'):
            compile_mirror(self.zone, [], [('x.lab.test.', 'x.lab.test.')], {}, 0)
        aliases = [('a.lab.test.', 'b.lab.test.'), ('b.lab.test.', 'c.lab.test.'),
                   ('c.lab.test.', 'a.lab.test.')]
        with self.assertRaisesRegex(DnsError, 'cycle'):
            compile_mirror(self.zone, [], aliases, {}, 0)

    def test_dangling_chain(self):
        aliases = [('api.lab.test.', 'svc.lab.test.')]
        with self.assertRaisesRegex(DnsError, 'dangling'):
            compile_mirror(self.zone, self.bindings, aliases, {}, 0)
        # Chain whose tail leaves the alias map without reaching an A.
        aliases = [('a.lab.test.', 'b.lab.test.'), ('b.lab.test.', 'c.lab.test.')]
        with self.assertRaisesRegex(DnsError, 'dangling'):
            compile_mirror(self.zone, [], aliases, {}, 0)

    def test_unbound_and_sleeping_binding(self):
        # Lease without a binding contributes nothing.
        records = compile_mirror(self.zone, self.bindings, [],
                                 {'X': (addr(7), 9)}, 5)
        self.assertEqual(records, [])
        # Dormant binding (no active lease) contributes nothing but a CNAME
        # may still point at the other live name.
        aliases = [('api.lab.test.', 'svc.lab.test.')]
        records = compile_mirror(self.zone, self.bindings, aliases,
                                 {'A': (addr(1), 20)}, 5)
        self.assertEqual({r['type'] for r in records}, {'A', 'CNAME', 'PTR'})

    def test_dormant_binding_activation_conflicts_with_cname(self):
        bindings = [('A', 'svc.lab.test.', False), ('B', 'api.lab.test.', False)]
        aliases = [('api.lab.test.', 'svc.lab.test.')]
        # B dormant: fine.
        compile_mirror(self.zone, bindings, aliases, {'A': (addr(1), 20)}, 5)
        # B active: same owner now wants both A and CNAME.
        with self.assertRaisesRegex(DnsError, 'also has active A'):
            compile_mirror(self.zone, bindings, aliases,
                           {'A': (addr(1), 20), 'B': (addr(2), 15)}, 5)

    def test_sorting_and_unique_owner_type(self):
        bindings = [('A', 'zeta.lab.test.', True), ('B', 'alpha.lab.test.', True)]
        active = {'A': (addr(1), 10), 'B': (addr(2), 11)}
        records = compile_mirror(self.zone, bindings, [], active, 0)
        keys = [(r['name'], r['type']) for r in records]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(keys), len(set(keys)))

    def test_fork_join_aliases(self):
        aliases = [('a1.lab.test.', 'join.lab.test.'),
                   ('a2.lab.test.', 'join.lab.test.'),
                   ('join.lab.test.', 'svc.lab.test.')]
        active = {'A': (addr(1), 20)}
        records = compile_mirror(self.zone, self.bindings, aliases, active, 5)
        self.assertEqual(records, ref_compile(self.zone, self.bindings, aliases, active, 5))
        for r in records:
            if r['type'] == 'CNAME':
                self.assertEqual(r['ttl'], 15)

    def test_long_chain_1500_levels_and_2048_aliases(self):
        zone = 'lab.test.'
        bindings = [('A', 'n0.lab.test.', False)]
        aliases = [('n%d.lab.test.' % i, 'n%d.lab.test.' % (i - 1)) for i in range(1, 1501)]
        active = {'A': (addr(1), 3000)}
        records = compile_mirror(zone, bindings, aliases, active, 0)
        self.assertEqual(len(records), 1501)  # one A plus 1500 CNAMEs
        self.assertTrue(all(r['ttl'] == 3000 for r in records))
        # A full 2048-entry fan-in onto one terminal A.
        many = [('fan%d.lab.test.' % i, 'n0.lab.test.') for i in range(2048)]
        records = compile_mirror(zone, bindings, many, active, 7)
        self.assertEqual(len(records), 2049)
        self.assertTrue(all(r['ttl'] == 2993 for r in records))

    def test_chain_over_recursion_limit_depth_iterative(self):
        # Far deeper than Python's default recursion limit; an iterative
        # compiler must still terminate deterministically.
        depth = 2048
        aliases = [('d%d.lab.test.' % i, 'd%d.lab.test.' % (i - 1))
                   for i in range(1, depth + 1)]
        bindings = [('A', 'd0.lab.test.', False)]
        records = compile_mirror('lab.test.', bindings, aliases,
                                 {'A': (addr(1), 100)}, 0)
        self.assertEqual(len(records), depth + 1)
        # Deep cycle is rejected rather than crashing with RecursionError.
        cyclic = aliases + [('d0.lab.test.', 'd%d.lab.test.' % depth)]
        with self.assertRaises(DnsError):
            compile_mirror('lab.test.', bindings, cyclic, {'A': (addr(1), 100)}, 0)

    def test_ptr_name_helper(self):
        self.assertEqual(ptr_name(addr(1)), '1.2.0.192.in-addr.arpa.')


class RandomizedReferenceCrossCheck(unittest.TestCase):
    def test_random_valid_mirrors_match_reference(self):
        import random
        rnd = random.Random(2026)
        zone = 'lab.test.'
        for trial in range(300):
            clients = ['c%d' % i for i in range(rnd.randint(0, 6))]
            names = ['svc%d.lab.test.' % i for i in range(rnd.randint(1, 4))]
            bindings = []
            for client in clients:
                bindings.append((client, rnd.choice(names) + '.', rnd.random() < 0.5))
            active = {client: (addr(rnd.randint(1, 6)), rnd.randint(11, 40))
                      for client in clients if rnd.random() < 0.7}
            now = rnd.randint(0, 10)
            active = {c: (a, e) for c, (a, e) in active.items() if e > now}
            # Aliases form chains/forks over a private name space plus svc names.
            alias_names = ['alias%d.lab.test.' % i for i in range(rnd.randint(0, 5))]
            all_targets = alias_names + names
            aliases = list(dict((owner, rnd.choice(all_targets))
                                for owner in alias_names).items())
            try:
                got = compile_mirror(zone, bindings, aliases, active, now)
            except DnsError:
                with self.assertRaises(DnsError):
                    ref_compile(zone, bindings, aliases, active, now)
                continue
            expected = ref_compile(zone, bindings, aliases, active, now)
            self.assertEqual(got, expected, trial)


if __name__ == '__main__':
    unittest.main()
