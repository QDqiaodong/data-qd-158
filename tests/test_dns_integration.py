import concurrent.futures
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from ipv4_leases.dns import DnsError
from ipv4_leases.pool import Pool

CIDR = '192.0.2.0/29'
ADDR = {last: int.from_bytes(bytes((192, 0, 2, last)), 'big') for last in range(8)}


def binding(client, name, reverse=False):
    return {'client': client, 'name': name, 'reverse': reverse}


def alias(name, target):
    return {'name': name, 'target': target}


class DnsBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'pool.sqlite'
        self.pool = Pool(self.path)
        self.pool.initialize(CIDR)

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def reopen(self):
        self.pool.close()
        self.pool = Pool(self.path)
        return self.pool

    def tables(self):
        return {row[0] for row in self.pool.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}

    def full_state(self):
        db = self.pool.db
        return {
            'clock': db.execute('SELECT clock FROM metadata').fetchone()[0],
            'leases': db.execute('SELECT client,address,expires FROM leases ORDER BY client').fetchall(),
            'external': db.execute(
                'SELECT address FROM external_dhcp_claims ORDER BY address').fetchall()
                if 'external_dhcp_claims' in self.tables() else [],
            'seq': db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall()
                   if 'history_events' in self.tables() else [],
            'zone': db.execute('SELECT zone FROM dns_meta').fetchone()
                    if 'dns_meta' in self.tables() else None,
            'dns_bindings': db.execute('SELECT client,name,reverse FROM dns_bindings ORDER BY client').fetchall()
                             if 'dns_bindings' in self.tables() else [],
            'dns_aliases': db.execute('SELECT owner,target FROM dns_aliases ORDER BY owner').fetchall()
                            if 'dns_aliases' in self.tables() else [],
        }


class AcceptanceOne(DnsBase):
    def config(self):
        return self.pool.configure_dns(5, 'lab.test', [
            binding('A', 'svc.lab.test', True),
            binding('B', 'svc.lab.test', False)], [alias('api.lab.test', 'svc.lab.test')])

    def test_clock5_mirror(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.operate('acquire', 0, 'B', 8)
        out = self.config()
        self.assertEqual(out['cidr'], CIDR)
        self.assertEqual(out['clock'], 5)
        self.assertEqual(out['zone'], 'lab.test.')
        names = {(r['name'], r['type']): r for r in out['records']}
        self.assertEqual(names[('svc.lab.test.', 'A')],
                         {'name': 'svc.lab.test.', 'type': 'A', 'ttl': 3,
                          'values': ['192.0.2.1', '192.0.2.2']})
        self.assertEqual(names[('api.lab.test.', 'CNAME')],
                         {'name': 'api.lab.test.', 'type': 'CNAME', 'ttl': 3,
                          'values': ['svc.lab.test.']})
        self.assertEqual(names[('1.2.0.192.in-addr.arpa.', 'PTR')],
                         {'name': '1.2.0.192.in-addr.arpa.', 'type': 'PTR', 'ttl': 15,
                          'values': ['svc.lab.test.']})
        self.assertEqual([(r['name'], r['type']) for r in out['records']],
                         sorted((r['name'], r['type']) for r in out['records']))
        # Snapshot returns the identical structure after reopen.
        self.assertEqual(self.reopen().dns_snapshot(), out)

    def test_after_list8_b_expires_and_ttls_shift(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.operate('acquire', 0, 'B', 8)
        self.config()
        self.pool.operate('list', 8)
        snap = self.pool.dns_snapshot()
        self.assertEqual(snap['clock'], 8)
        names = {(r['name'], r['type']): r for r in snap['records']}
        self.assertEqual(names[('svc.lab.test.', 'A')]['values'], ['192.0.2.1'])
        self.assertEqual(names[('svc.lab.test.', 'A')]['ttl'], 12)
        self.assertEqual(names[('api.lab.test.', 'CNAME')]['ttl'], 12)
        self.assertEqual(names[('1.2.0.192.in-addr.arpa.', 'PTR')]['ttl'], 12)
        self.assertEqual([r['name'] for r in snap['records'] if r['type'] == 'PTR'],
                         ['1.2.0.192.in-addr.arpa.'])

    def test_persistence_tables_have_no_materialised_records(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.config()
        self.assertEqual(self.tables() & {'dns_meta', 'dns_bindings', 'dns_aliases'},
                         {'dns_meta', 'dns_bindings', 'dns_aliases'})
        self.assertEqual(self.pool.db.execute('SELECT * FROM dns_bindings').fetchall(),
                         [('A', 'svc.lab.test.', 1), ('B', 'svc.lab.test.', 0)])


class LinkageRollback(DnsBase):
    def install(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 20)
        bindings = [binding('A', 'svc.lab.test'), binding('B', 'api.lab.test')]
        self.pool.configure_dns(0, 'lab.test', bindings,
                                [alias('api.lab.test', 'svc.lab.test')])
        return bindings

    def test_acquire_conflict_and_release_dangle_roll_back(self):
        bindings = self.install()
        before = self.full_state()
        with self.assertRaisesRegex(DnsError, 'also has active A'):
            self.pool.operate('acquire', 5, 'B', 10)
        self.assertEqual(self.full_state(), before)
        with self.assertRaisesRegex(DnsError, 'dangling'):
            self.pool.operate('release', 5, 'A')
        self.assertEqual(self.full_state(), before)

    def test_reconfigure_drops_alias_then_acquire_succeeds(self):
        bindings = self.install()
        out = self.pool.configure_dns(5, 'lab.test', bindings, [])
        self.assertEqual({(r['name'], r['type']) for r in out['records']},
                         {('svc.lab.test.', 'A')})
        acquired = self.pool.operate('acquire', 5, 'B', 10)
        self.assertEqual([x for x in acquired['leases'] if x['client'] == 'B'][0]['address'],
                         '192.0.2.2')
        names = {r['name']: r for r in self.pool.dns_snapshot()['records']}
        self.assertEqual(names['svc.lab.test.']['ttl'], 15)
        self.assertEqual(names['api.lab.test.']['ttl'], 10)
        self.assertEqual(names['api.lab.test.']['type'], 'A')
        self.assertNotIn('CNAME', [r['type'] for r in self.pool.dns_snapshot()['records']])


class ExpiryDangling(DnsBase):
    def test_list_at_expiry_rolls_back_everything(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 10)
        bindings = [binding('A', 'svc.lab.test')]
        self.pool.configure_dns(0, 'lab.test', bindings,
                                [alias('api.lab.test', 'svc.lab.test')])
        before = self.full_state()
        with self.assertRaisesRegex(DnsError, 'dangling'):
            self.pool.operate('list', 10)
        self.assertEqual(self.full_state(), before)

    def test_reconfigure_at_expiry_clears_and_yields_empty_mirror(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 10)
        bindings = [binding('A', 'svc.lab.test')]
        self.pool.configure_dns(0, 'lab.test', bindings,
                                [alias('api.lab.test', 'svc.lab.test')])
        out = self.pool.configure_dns(10, 'lab.test', bindings, [])
        self.assertEqual(out['records'], [])
        self.assertEqual(out['clock'], 10)
        self.assertEqual(self.pool.db.execute('SELECT client FROM leases').fetchall(), [])
        self.assertEqual(self.pool.dns_snapshot()['records'], [])


class GuardsAcrossWriteEntries(DnsBase):
    def use_alias(self):
        self.pool.operate('acquire', 0, 'A', 20)
        bindings = [binding('A', 'svc.lab.test'), binding('B', 'api.lab.test')]
        self.pool.configure_dns(0, 'lab.test', bindings,
                                [alias('api.lab.test', 'svc.lab.test')])
        return bindings

    def test_reconcile_guard(self):
        bindings = self.use_alias()
        before = self.full_state()
        # Authoritative set activates B on .2: A/CNAME collision.
        with self.assertRaises(DnsError):
            self.pool.reconcile(5, [
                {'client': 'A', 'ttl': 15, 'allowed': ['192.0.2.1/32']},
                {'client': 'B', 'ttl': 10, 'allowed': ['192.0.2.2/32']}], [])
        self.assertEqual(self.full_state(), before)
        # Reconcile that drops A dangles the alias.
        with self.assertRaises(DnsError):
            self.pool.reconcile(5, [
                {'client': 'B', 'ttl': 10, 'allowed': ['192.0.2.2/32']}], [])
        self.assertEqual(self.full_state(), before)

    def test_reconcile_success_keeps_original_objective(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 20)
        bindings = [binding('A', 'svc.lab.test', True)]
        self.pool.configure_dns(0, 'lab.test', bindings, [])
        out = self.pool.reconcile(5, [
            {'client': 'A', 'ttl': 10, 'allowed': ['192.0.2.0/29']}], [])
        self.assertEqual(out['moved_clients'], [])
        self.assertEqual(out['leases'][0]['address'], '192.0.2.1')
        self.assertEqual(self.pool.dns_snapshot()['clock'], 5)

    def test_import_dhcp_guard_when_last_a_is_reaped(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from pcapbuild import ack_facts_capture
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 10)
        bindings = [binding('A', 'svc.lab.test')]
        self.pool.configure_dns(0, 'lab.test', bindings,
                                [alias('api.lab.test', 'svc.lab.test')])
        # ACK on .2 is harmless on its own; the failure is the expiry reaping
        # of the only A RRset that the alias depends on.
        capture = Path(self.tmp.name) / 'c.pcap'
        capture.write_bytes(ack_facts_capture([(4, ADDR[2], 10)]))
        before = self.full_state()
        with self.assertRaises(DnsError):
            self.pool.import_dhcp(10, capture)
        self.assertEqual(self.full_state(), before)
        self.assertNotIn('external_dhcp_claims', self.tables())

    def test_import_dhcp_success_with_valid_mirror(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from pcapbuild import ack_facts_capture
        self.pool.operate('acquire', 0, 'A', 30)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        capture = Path(self.tmp.name) / 'c.pcap'
        capture.write_bytes(ack_facts_capture([(4, ADDR[2], 10)]))
        out = self.pool.import_dhcp(8, capture)
        self.assertEqual(out['clock'], 8)
        self.assertEqual(len(out['claims']), 1)
        # External facts never generate DNS records.
        names = {r['name'] for r in self.pool.dns_snapshot()['records']}
        self.assertEqual(names, {'svc.lab.test.'})


class ConfigurationReplacement(DnsBase):
    def test_full_replacement_does_not_keep_deleted_parts(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')],
                                [alias('api.lab.test', 'svc.lab.test')])
        out = self.pool.configure_dns(2, 'other.test',
                                      [binding('A', 'host.other.test', True)], [])
        self.assertEqual(out['zone'], 'other.test.')
        self.assertEqual({r['name'] for r in out['records']},
                         {'host.other.test.', '1.2.0.192.in-addr.arpa.'})
        raw = self.full_state()
        self.assertEqual(raw['zone'], ('other.test.',))
        self.assertEqual(raw['dns_aliases'], [])

    def test_release_and_reconcile_deletion_dangle_the_alias(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')],
                                [alias('api.lab.test', 'svc.lab.test')])
        before = self.full_state()
        with self.assertRaisesRegex(DnsError, 'dangling'):
            self.pool.operate('release', 3, 'A')
        self.assertEqual(self.full_state(), before)
        # Reconcile authoritative set that deletes A dangles identically.
        with self.assertRaisesRegex(DnsError, 'dangling'):
            self.pool.reconcile(3, [], [])
        self.assertEqual(self.full_state(), before)

    def test_zone_change_moves_every_record_to_new_zone(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(0, 'lab.test',
                                [binding('A', 'svc.lab.test', True)],
                                [alias('api.lab.test', 'svc.lab.test')])
        out = self.pool.configure_dns(4, 'corp.example',
                                      [binding('A', 'svc.corp.example', True)],
                                      [alias('api.corp.example', 'svc.corp.example')])
        owners = {r['name'] for r in out['records']}
        self.assertEqual(owners, {
            'svc.corp.example.', 'api.corp.example.', '1.2.0.192.in-addr.arpa.'})
        self.assertTrue(all(n.endswith('corp.example.') or n.endswith('in-addr.arpa.')
                            for n in owners))
        # No lab.test names survive anywhere in the stored config.
        rows = self.pool.db.execute('SELECT name FROM dns_bindings UNION ALL '
                                    'SELECT owner FROM dns_aliases UNION ALL '
                                    'SELECT target FROM dns_aliases').fetchall()
        self.assertTrue(all('lab.test' not in r[0] for r in rows))

    def test_empty_configuration_is_valid_and_clears_mirror(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')],
                                [alias('api.lab.test', 'svc.lab.test')])
        out = self.pool.configure_dns(3, 'lab.test', [], [])
        self.assertEqual(out['records'], [])
        self.assertEqual(self.pool.dns_snapshot()['records'], [])
        # The lease itself is untouched.
        self.assertEqual(len(self.pool.db.execute('SELECT client FROM leases').fetchall()), 1)

    def test_backward_clock_rejected_without_changes(self):
        self.pool.operate('list', 5)
        before = self.full_state()
        with self.assertRaisesRegex(ValueError, 'clock cannot move backward'):
            self.pool.configure_dns(4, 'lab.test', [], [])
        self.assertEqual(self.full_state(), before)
        self.assertNotIn('dns_meta', self.tables())

    def test_bad_config_creates_no_tables(self):
        self.pool.operate('acquire', 0, 'A', 20)
        for kwargs in (
                dict(now=0, zone='lab.test',
                     bindings=[binding('A', 'outside.example')], aliases=[]),
                dict(now=0, zone='lab.test', bindings=[],
                     aliases=[alias('lab.test', 'svc.lab.test')]),
                dict(now=0, zone='lab.test', bindings=[],
                     aliases=[alias('a.lab.test', 'b.lab.test')])):
            with self.assertRaises(DnsError):
                self.pool.configure_dns(**kwargs)
        self.assertNotIn('dns_meta', self.tables())

    def test_same_config_reenqueues_one_history_event(self):
        self.pool.enable_history()
        cfg = dict(zone='lab.test', bindings=[binding('A', 'svc.lab.test')], aliases=[])
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(now=1, **cfg)
        seq_before = self.pool.db.execute('SELECT MAX(seq) FROM history_events').fetchone()[0]
        self.pool.configure_dns(now=2, **cfg)
        seq_after = self.pool.db.execute('SELECT MAX(seq) FROM history_events').fetchone()[0]
        self.assertEqual(seq_after, seq_before + 1)
        self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0], 2)

    def test_history_disabled_pool_gets_dns_without_history(self):
        # Legacy pool without history tables.
        for name in ('history_changes', 'history_events', 'history_meta'):
            self.pool.db.execute('DROP TABLE IF EXISTS %s' % name)
        self.pool.db.commit()
        self.pool.operate('acquire', 0, 'A', 20)
        out = self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        self.assertEqual(len(out['records']), 1)
        self.assertNotIn('history_events', self.tables())

    def test_init_and_history_enable_leave_dns_alone(self):
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        snapshot = self.full_state()
        self.pool.initialize(CIDR)
        self.pool.enable_history()
        self.assertEqual({k: v for k, v in self.full_state().items()
                          if k.startswith('dns') or k == 'zone'},
                         {k: v for k, v in snapshot.items()
                          if k.startswith('dns') or k == 'zone'})


class SnapshotSemantics(DnsBase):
    def test_unconfigured_snapshot_fails_without_creating_storage(self):
        with self.assertRaises(DnsError):
            self.pool.dns_snapshot()
        self.assertNotIn('dns_meta', self.tables())
        # Even after other writes, storage still absent.
        self.pool.operate('acquire', 0, 'A', 5)
        self.pool.operate('list', 1)
        self.assertNotIn('dns_meta', self.tables())

    def test_snapshot_is_read_only(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        before = self.full_state()
        for _ in range(3):
            self.pool.dns_snapshot()
        self.assertEqual(self.full_state(), before)

    def test_snapshot_uses_stored_clock_not_caller_now(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(5, 'lab.test', [binding('A', 'svc.lab.test')], [])
        snap = self.pool.dns_snapshot()
        self.assertEqual(snap['clock'], 5)
        self.assertEqual(snap['records'][0]['ttl'], 15)

    def test_damaged_table_error_propagates(self):
        self.pool.operate('acquire', 0, 'A', 20)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        self.pool.db.execute('DROP TABLE dns_bindings')
        self.pool.db.commit()
        with self.assertRaises(sqlite3.Error):
            self.pool.dns_snapshot()
        with self.assertRaises(sqlite3.Error):
            self.pool.operate('list', 1)


class LegacyBehavior(DnsBase):
    def test_legacy_writes_never_create_dns_tables(self):
        self.pool.operate('acquire', 0, 'A', 10)
        self.pool.operate('release', 2, 'A')
        self.pool.operate('list', 3)
        self.pool.reconcile(4, [], [])
        self.assertEqual(self.tables() & {'dns_meta', 'dns_bindings', 'dns_aliases'}, set())

    def test_legacy_responses_carry_no_dns_fields(self):
        out = self.pool.operate('acquire', 0, 'A', 10)
        self.assertEqual(set(out), {'cidr', 'clock', 'leases'})
        rec = self.pool.reconcile(1, [], [])
        self.assertEqual(set(rec), {'cidr', 'clock', 'leases', 'moved_clients'})


class FaultInjection(DnsBase):
    def test_config_write_failure_rolls_back_everything(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 20)
        # Establish the storage first, then arm a trigger so a replacement
        # fails mid-write inside its own transaction.
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        self.pool.db.execute(
            "CREATE TRIGGER boom BEFORE INSERT ON dns_aliases "
            "BEGIN SELECT RAISE(ABORT,'injected dns write'); END")
        before = self.full_state()
        with self.assertRaises(sqlite3.Error):
            self.pool.configure_dns(5, 'lab.test', [binding('A', 'svc.lab.test')],
                                   [alias('api.lab.test', 'svc.lab.test')])
        self.assertEqual(self.full_state(), before)
        self.pool.db.execute('DROP TRIGGER boom')
        # A later valid attempt still works.
        out = self.pool.configure_dns(5, 'lab.test', [binding('A', 'svc.lab.test')], [])
        self.assertEqual(out['clock'], 5)

    def test_history_write_failure_rolls_back_dns_config(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 20)  # consumes seq 1
        self.pool.db.execute(
            "CREATE TRIGGER boom BEFORE INSERT ON history_events "
            "WHEN NEW.seq>1 BEGIN SELECT RAISE(ABORT,'injected history'); END")
        before = self.full_state()
        with self.assertRaises(sqlite3.Error):
            self.pool.configure_dns(3, 'lab.test', [binding('A', 'svc.lab.test')], [])
        self.assertEqual(self.full_state(), before)
        self.pool.db.execute('DROP TRIGGER boom')

    def test_lease_guard_failure_after_config_write_rolls_back_config(self):
        self.pool.enable_history()
        # Alias whose chain is dangling against the final leases: the config
        # rows are installed before the mirror check and must roll back with it.
        before = self.full_state()
        with self.assertRaises(DnsError):
            self.pool.configure_dns(2, 'lab.test', [],
                                   [alias('api.lab.test', 'svc.lab.test')])
        self.assertEqual(self.full_state(), before)


class TwoConnectionInterleaving(DnsBase):
    def test_snapshot_always_sees_one_complete_commit(self):
        self.pool.operate('acquire', 0, 'A', 40)
        self.pool.configure_dns(0, 'lab.test', [binding('A', 'svc.lab.test')], [])
        barrier = threading.Barrier(3)
        errors = []

        def reconfigure(_):
            p = Pool(self.path)
            try:
                barrier.wait()
                p.configure_dns(10, 'new.test', [binding('A', 'host.new.test')], [])
            except Exception as exc:  # serialization losers must retry-free fail loudly if any
                errors.append(exc)
            finally:
                p.close()

        def snapshot(_):
            p = Pool(self.path)
            try:
                barrier.wait()
                report = p.dns_snapshot()
                # Clock and zone must originate from the same commit.
                if report['zone'] == 'new.test.':
                    self.assertEqual(report['clock'], 10)
                    self.assertEqual({r['name'] for r in report['records']}, {'host.new.test.'})
                else:
                    self.assertEqual(report['clock'], 0)
                    self.assertEqual({r['name'] for r in report['records']}, {'svc.lab.test.'})
            finally:
                p.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(reconfigure, 0)] + [executor.submit(snapshot, i) for i in range(2)]
            for future in futures:
                future.result()
        self.assertEqual(errors, [])

    def test_acquire_waits_for_new_config_and_obeys_it(self):
        self.pool.operate('acquire', 0, 'A', 20)
        bindings = [binding('A', 'svc.lab.test'), binding('B', 'api.lab.test')]
        self.pool.configure_dns(0, 'lab.test', bindings,
                                [alias('api.lab.test', 'svc.lab.test')])
        barrier = threading.Barrier(2)

        def drop_alias(_):
            p = Pool(self.path)
            try:
                barrier.wait()
                p.configure_dns(5, 'lab.test', bindings, [])
            finally:
                p.close()

        def try_acquire(_):
            p = Pool(self.path)
            try:
                barrier.wait()
                try:
                    return p.operate('acquire', 5, 'B', 10)
                except DnsError:
                    return None
            finally:
                p.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f_reconfig = executor.submit(drop_alias, 0)
            f_acquire = executor.submit(try_acquire, 1)
            reconfig_result, acquired = f_reconfig.result(), f_acquire.result()
        self.assertIsNone(reconfig_result)
        if acquired is None:
            self.pool.operate('acquire', 5, 'B', 10)
        else:
            self.assertEqual([x for x in acquired['leases'] if x['client'] == 'B'][0]['address'],
                             '192.0.2.2')
        self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0], 5)

    def test_conflicting_config_and_release_never_both_commit(self):
        for _ in range(8):
            self.pool.close()
            self.tmp.cleanup()
            self.tmp = tempfile.TemporaryDirectory()
            self.path = Path(self.tmp.name) / 'pool.sqlite'
            self.pool = Pool(self.path)
            self.pool.initialize(CIDR)
            self.pool.enable_history()
            self.pool.operate('acquire', 0, 'A', 20)
            bindings = [binding('A', 'svc.lab.test')]
            barrier = threading.Barrier(2)

            def add_alias(_):
                q = Pool(self.path)
                try:
                    barrier.wait()
                    try:
                        q.configure_dns(5, 'lab.test', bindings,
                                        [alias('api.lab.test', 'svc.lab.test')])
                        return 'configured'
                    except DnsError:
                        return 'rejected'
                finally:
                    q.close()

            def release(_):
                q = Pool(self.path)
                try:
                    barrier.wait()
                    try:
                        q.operate('release', 5, 'A')
                        return 'released'
                    except DnsError:
                        return 'rejected'
                finally:
                    q.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                cfg, rel = [f.result() for f in
                            (executor.submit(add_alias, 0), executor.submit(release, 1))]
            # The two operations cannot both commit (that would leave a
            # dangling alias or a deleted A under a live CNAME).
            self.assertFalse(cfg == 'configured' and rel == 'released')
            # Whichever committed, the final state still compiles cleanly.
            if self.pool._dns_enabled():
                self.pool.dns_snapshot()


class DnsCli(DnsBase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'ipv4_leases.admin',
                               '--db', str(self.path), *args],
                              capture_output=True, text=True)

    def write(self, name, payload):
        target = Path(self.tmp.name) / name
        if isinstance(payload, bytes):
            target.write_bytes(payload)
        else:
            target.write_text(json.dumps(payload))
        return target

    def test_config_and_snapshot_round_trip(self):
        self.run_cli('acquire', '--now', '0', '--client', 'A', '--ttl', '20')
        source = self.write('dns.json', {
            'now': 5, 'zone': 'lab.test',
            'bindings': [binding('A', 'svc.lab.test', True)],
            'aliases': [alias('api.lab.test', 'svc.lab.test')]})
        done = self.run_cli('dns-config', '--source', str(source))
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        self.assertEqual(set(payload), {'cidr', 'clock', 'zone', 'records', 'source_sha256'})
        self.assertEqual(payload['source_sha256'],
                         __import__('hashlib').sha256(source.read_bytes()).hexdigest())
        output = Path(self.tmp.name) / 'snap.json'
        done = self.run_cli('dns-snapshot', '--output', str(output))
        self.assertEqual(done.returncode, 0, done.stderr)
        snap = json.loads(done.stdout)
        self.assertEqual(set(snap), {'cidr', 'clock', 'zone', 'records'})
        self.assertEqual(json.loads(output.read_text()), snap)
        self.assertEqual(self.pool.dns_snapshot(), snap)

    def test_unconfigured_snapshot_cli_fails_and_keeps_old_report(self):
        output = Path(self.tmp.name) / 'snap.json'
        output.write_text('old-report')
        done = self.run_cli('dns-snapshot', '--output', str(output))
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, '')
        self.assertIn('DNS not configured', done.stderr)
        self.assertEqual(output.read_text(), 'old-report')

    def test_path_and_symlink_guards(self):
        source = self.write('dns.json', {'now': 0, 'zone': 'lab.test',
                                         'bindings': [], 'aliases': []})
        same = self.run_cli('dns-config', '--source', str(self.path))
        self.assertEqual(same.returncode, 2)
        self.assertIn('must differ', same.stderr)
        link = Path(self.tmp.name) / 'link.json'
        link.symlink_to(source)
        self.assertEqual(self.run_cli('dns-config', '--source', str(link)).returncode, 2)
        out_link = Path(self.tmp.name) / 'outlink.json'
        out_link.symlink_to(source)
        self.assertEqual(self.run_cli('dns-snapshot', '--output', str(out_link)).returncode, 2)
        # A source path that is another hardlink name for the database inode.
        source_link = Path(self.tmp.name) / 'db-alias.json'
        os.link(self.path, source_link)
        done = self.run_cli('dns-config', '--source', str(source_link))
        self.assertEqual(done.returncode, 2)
        self.assertIn('hardlink', done.stderr)
        # A snapshot output path that is another hardlink name for the db inode.
        out_hard = Path(self.tmp.name) / 'outhard.json'
        os.link(self.path, out_hard)
        done = self.run_cli('dns-snapshot', '--output', str(out_hard))
        self.assertEqual(done.returncode, 2)
        self.assertIn('hardlink', done.stderr)

    def test_strict_json_inputs(self):
        cases = [
            b'{"now":0,"zone":"lab.test","bindings":[],"aliases":[],"x":1}',
            b'{"now":0,"now":1,"zone":"lab.test","bindings":[],"aliases":[]}',
            b'{"now":true,"zone":"lab.test","bindings":[],"aliases":[]}',
            b'{"now":0,"zone":"lab.test","bindings":[{"client":"A","name":"a.lab.test","reverse":1}],"aliases":[]}',
            b'{"now":0,"zone":"lab.test","bindings":[{"client":"A","name":"bad name","reverse":false}],"aliases":[]}',
            b'not json',
        ]
        for raw in cases:
            source = self.write('bad.json', raw)
            done = self.run_cli('dns-config', '--source', str(source))
            self.assertEqual(done.returncode, 2, raw)
            self.assertEqual(done.stdout, '')

    def test_missing_database_is_not_created(self):
        missing = Path(self.tmp.name) / 'missing.sqlite'
        source = self.write('dns.json', {'now': 0, 'zone': 'lab.test',
                                         'bindings': [], 'aliases': []})
        done = subprocess.run([sys.executable, '-m', 'ipv4_leases.admin',
                               '--db', str(missing), 'dns-config', '--source', str(source)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertFalse(missing.exists())


class Slash31And32(DnsBase):
    def build(self, cidr, address_last):
        path = Path(self.tmp.name) / (cidr.replace('/', '_') + '.sqlite')
        pool = Pool(path)
        pool.initialize(cidr)
        pool.operate('acquire', 0, 'A', 20)
        out = pool.configure_dns(5, 'lab.test', [binding('A', 'svc.lab.test', True)], [])
        by_type = {r['type']: r for r in out['records']}
        self.assertEqual(by_type['A']['values'], ['192.0.2.%d' % address_last])
        self.assertEqual(pool.dns_snapshot()['clock'], 5)
        self.assertEqual(by_type['PTR']['ttl'], 15)
        pool.close()

    def test_small_pools(self):
        self.build('192.0.2.0/31', 0)
        self.build('192.0.2.9/32', 9)


if __name__ == '__main__':
    unittest.main()
