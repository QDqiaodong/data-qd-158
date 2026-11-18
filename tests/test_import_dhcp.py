import hashlib, ipaddress, json, sqlite3, struct, subprocess, sys, tempfile, unittest
import concurrent.futures
from pathlib import Path
from ipv4_leases.pool import Pool
from pcapbuild import (ack_facts_capture, dhcp_message, standard_options,
                      udp_segment, ethernet_frame, fragment_datagram,
                      pcap_file, DEFAULT_SERVER, DEFAULT_MAC)

ADDR = {last: int(ipaddress.IPv4Address('192.0.2.%d' % last)) for last in range(8)}
MAC2 = b'\x01\x02\x03\x04\x05\x06'
SERVER2 = 0x0A00000A


def strip_history(pool):
    for name in ('history_changes', 'history_events', 'history_meta'):
        pool.db.execute(f'DROP TABLE IF EXISTS {name}')
    pool.db.commit()


def strip_external(pool):
    pool.db.execute('DROP TABLE IF EXISTS external_dhcp_claims')
    pool.db.commit()


def demand(client, ttl, *allowed):
    return {'client': client, 'ttl': ttl, 'allowed': list(allowed)}


class ImportBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'pool.sqlite'
        self.pool = Pool(self.path)
        self.pool.initialize('192.0.2.0/29')

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def write(self, name, raw):
        target = Path(self.tmp.name) / name
        target.write_bytes(raw)
        return target

    def ack_capture(self, records, name='capture.pcap', endian='<'):
        return self.write(name, ack_facts_capture(records, endian=endian))

    def snapshot(self):
        db = self.pool.db
        external = []
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='external_dhcp_claims'").fetchone():
            external = db.execute(
                'SELECT server,mac,address,observed_at,ttl,expires '
                'FROM external_dhcp_claims ORDER BY address,server,mac').fetchall()
        history = []
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='history_events'").fetchone():
            history = db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall()
        return {
            'clock': db.execute('SELECT clock FROM metadata').fetchone()[0],
            'leases': db.execute('SELECT client,address,expires FROM leases ORDER BY address').fetchall(),
            'external': external,
            'seq': history,
        }


class AcceptanceScenario(ImportBase):
    def build_two_ack_capture(self):
        return self.ack_capture([(4, ADDR[1], 10), (4, ADDR[2], 10)])

    def test_full_acceptance_flow(self):
        self.pool.operate('acquire', 0, 'A', 30)
        capture = self.build_two_ack_capture()
        result = self.pool.import_dhcp(8, capture)
        self.assertEqual(result['clock'], 8)
        self.assertEqual([c['address'] for c in result['claims']], ['192.0.2.1', '192.0.2.2'])
        self.assertEqual(result['conflicts'], [{
            'address': '192.0.2.1', 'client': 'A',
            'claims': [result['claims'][0]]}])
        self.assertEqual(result['source_sha256'], hashlib.sha256(capture.read_bytes()).hexdigest())
        # B is a new client and takes the smallest free address excluding .1/.2.
        acquired = self.pool.operate('acquire', 8, 'B', 20)
        self.assertEqual([x['address'] for x in acquired['leases'] if x['client'] == 'B'], ['192.0.2.3'])
        # A's renewal must fail and never silently move A.
        with self.assertRaisesRegex(ValueError, 'external DHCP claim'):
            self.pool.operate('acquire', 8, 'A', 5)
        # Reconcile restricted to the externally held .2 is infeasible.
        with self.assertRaisesRegex(ValueError, 'no complete allocation'):
            self.pool.reconcile(8, [demand('A', 5, '192.0.2.2/32')], [])
        self.assertEqual(self.snapshot()['clock'], 8)
        self.assertEqual(self.snapshot()['leases'],
                         [('A', ADDR[1], 30), ('B', ADDR[3], 28)])
        # At 14 the claims have expired; a new client C gets .2.
        later = self.pool.operate('acquire', 14, 'C', 6)
        self.assertEqual([x['address'] for x in later['leases'] if x['client'] == 'C'], ['192.0.2.2'])

    def test_reimport_does_not_extend_expiry(self):
        self.pool.operate('acquire', 0, 'A', 30)
        first = self.build_two_ack_capture()
        self.pool.import_dhcp(8, first)
        # Same bytes reachable through a different path: fact identity ignores path/SHA.
        second = self.write('copy.pcap', first.read_bytes())
        again = self.pool.import_dhcp(10, second)
        self.assertEqual([c['expires'] for c in again['claims']], [14, 14])
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM external_dhcp_claims').fetchone()[0], 2)
        # A re-import at 14 cannot revive facts whose expires == now.
        expired = self.pool.import_dhcp(14, second)
        self.assertEqual(expired['claims'], [])
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM external_dhcp_claims').fetchone()[0], 0)

    def test_expiry_equals_now_is_invalid(self):
        # observed_at=4, ttl=4 -> expires=8 == now, so no fact survives.
        capture = self.ack_capture([(4, ADDR[5], 4)])
        result = self.pool.import_dhcp(8, capture)
        self.assertEqual(result['claims'], [])
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM external_dhcp_claims').fetchone()[0], 0)


class ReassemblyAtomicity(ImportBase):
    def test_interleaved_fragments_produce_canonical_facts(self):
        a = udp_segment(dhcp_message(ADDR[1], 10, options=standard_options(10)))
        b = udp_segment(dhcp_message(ADDR[2], 10, options=standard_options(10)))
        fa = fragment_datagram(a, 31, [48, 120])
        fb = fragment_datagram(b, 32, [40, 160])
        records = [(4, fa[2]), (4, fb[0]), (4, fa[0]), (5, fb[2]), (5, fa[1]), (5, fb[1])]
        capture = self.write('frag.pcap', pcap_file(records))
        result = self.pool.import_dhcp(8, capture)
        self.assertEqual([c['address'] for c in result['claims']], ['192.0.2.1', '192.0.2.2'])
        self.assertEqual({c['observed_at'] for c in result['claims']}, {4})

    def _fragmented_capture(self):
        segment = udp_segment(dhcp_message(ADDR[4], 10, options=standard_options(10)))
        return segment, fragment_datagram(segment, 41, [48, 120])

    def test_late_conflicting_fragment_rejects_everything(self):
        segment, frames = self._fragmented_capture()
        good = ethernet_frame(udp_segment(dhcp_message(ADDR[5], 10, options=standard_options(10))), 42)
        mutated = bytearray(frames[1])
        mutated[-1] ^= 0x01
        before = self.snapshot()
        capture = self.write('bad.pcap', pcap_file([(4, good), (4, frames[0]), (4, bytes(mutated)), (4, frames[2])]))
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, capture)
        self.assertEqual(self.snapshot(), before)
        # Even the well-formed other datagram must not have been persisted.
        self.assertEqual(self.snapshot()['external'], [])

    def test_contradictory_terminal_and_hole_roll_back(self):
        segment, frames = self._fragmented_capture()
        before = self.snapshot()
        extra = ethernet_frame(b'\x00' * 8, 41, mf=False, fragment_offset=len(segment) // 8 + 1)
        bad_terminal = self.write('term.pcap', pcap_file([(4, frames[0]), (4, frames[1]), (4, extra)]))
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, bad_terminal)
        hole = self.write('hole.pcap', pcap_file([(4, frames[0]), (4, frames[1])]))
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, hole)
        self.assertEqual(self.snapshot(), before)


class ClaimsAndConflicts(ImportBase):
    def test_independent_servers_and_macs_are_kept(self):
        records = [
            (4, ADDR[6], 10, DEFAULT_SERVER, DEFAULT_MAC),
            (4, ADDR[6], 10, SERVER2, MAC2),
        ]
        capture = self.write('multi.pcap', ack_facts_capture(records))
        result = self.pool.import_dhcp(8, capture)
        self.assertEqual(len(result['claims']), 2)
        # Sort key is (address, server numeric, mac string, observed_at, ttl).
        self.assertEqual([c['server'] for c in result['claims']],
                         ['10.0.0.9', '10.0.0.10'])
        self.assertEqual([c['mac'] for c in result['claims']],
                         ['aa:bb:cc:dd:ee:ff', '01:02:03:04:05:06'])

    def test_claims_sort_and_inner_conflict_claims(self):
        self.pool.operate('acquire', 0, 'A', 30)  # A -> .1
        records = [
            (4, ADDR[2], 10, SERVER2, MAC2),
            (4, ADDR[1], 10, DEFAULT_SERVER, DEFAULT_MAC),
            (4, ADDR[1], 10, SERVER2, MAC2),
        ]
        capture = self.write('sort.pcap', ack_facts_capture(records))
        result = self.pool.import_dhcp(8, capture)
        addresses = [c['address'] for c in result['claims']]
        self.assertEqual(addresses, ['192.0.2.1', '192.0.2.1', '192.0.2.2'])
        conflict = result['conflicts'][0]
        self.assertEqual(conflict['address'], '192.0.2.1')
        self.assertEqual(conflict['client'], 'A')
        self.assertEqual([c['server'] for c in conflict['claims']], ['10.0.0.9', '10.0.0.10'])

    def test_outside_pool_and_expired_acks_ignored(self):
        outside = int(ipaddress.IPv4Address('198.51.100.7'))
        capture = self.ack_capture([(4, outside, 10), (4, ADDR[3], 2)])
        result = self.pool.import_dhcp(8, capture)
        self.assertEqual(result['claims'], [])
        self.assertEqual(result['conflicts'], [])

    def test_empty_and_non_target_captures(self):
        empty = self.write('empty.pcap', pcap_file([]))
        result = self.pool.import_dhcp(8, empty)
        self.assertEqual(result['claims'], [])
        self.assertEqual(result['conflicts'], [])
        self.assertEqual(result['clock'], 8)
        # A capture whose only frames are non-DHCP still commits the clock.
        noise = ethernet_frame(udp_segment(b'\x00' * 300, src_port=1067, dst_port=1068), 9)
        target = self.write('noise.pcap', pcap_file([(4, noise)]))
        result = self.pool.import_dhcp(9, target)
        self.assertEqual(result['claims'], [])


class AllocationExclusion(ImportBase):
    def test_new_client_skips_external_addresses(self):
        capture = self.ack_capture([(4, ADDR[1], 20), (4, ADDR[2], 20)])
        self.pool.import_dhcp(8, capture)
        result = self.pool.operate('acquire', 8, 'B', 5)
        self.assertEqual(result['leases'][0]['address'], '192.0.2.3')

    def test_reconcile_excludes_claims_inside_transaction(self):
        capture = self.ack_capture([(4, ADDR[1], 20)])
        self.pool.import_dhcp(8, capture)
        result = self.pool.reconcile(8, [demand('A', 5, '192.0.2.0/29')], [])
        self.assertEqual(result['leases'][0]['address'], '192.0.2.2')
        # Excluding every usable address makes reconcile infeasible and the
        # whole transaction (including expiry cleanup and clock) rolls back.
        tight = self.ack_capture([(8, ADDR[2], 20), (8, ADDR[3], 20),
                                  (8, ADDR[4], 20), (8, ADDR[5], 20),
                                  (8, ADDR[6], 20)], name='tight.pcap')
        self.pool.import_dhcp(9, tight)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'no complete allocation'):
            self.pool.reconcile(9, [demand('A', 5, '192.0.2.0/29')], [])
        self.assertEqual(self.snapshot(), before)

    def test_slash31_and_slash32_pools(self):
        # /31: claim one host, the other host remains allocatable.
        pool31 = Pool(Path(self.tmp.name) / 'small1.sqlite')
        try:
            pool31.initialize('192.0.2.0/31')
            capture = Path(self.tmp.name) / 'small1.pcap'
            capture.write_bytes(ack_facts_capture([(4, ADDR[0], 10)]))
            result = pool31.import_dhcp(8, capture)
            self.assertEqual([c['address'] for c in result['claims']], ['192.0.2.0'])
            acquired = pool31.operate('acquire', 8, 'A', 5)
            self.assertEqual(acquired['leases'][0]['address'], '192.0.2.1')
        finally:
            pool31.close()
        # /32: the single host is claimed, so the pool is exhausted.
        pool32 = Pool(Path(self.tmp.name) / 'small2.sqlite')
        try:
            pool32.initialize('192.0.2.9/32')
            capture = Path(self.tmp.name) / 'small2.pcap'
            capture.write_bytes(ack_facts_capture([(4, int(ipaddress.IPv4Address('192.0.2.9')), 10)]))
            result = pool32.import_dhcp(8, capture)
            self.assertEqual([c['address'] for c in result['claims']], ['192.0.2.9'])
            with self.assertRaisesRegex(ValueError, 'exhausted'):
                pool32.operate('acquire', 8, 'A', 5)
        finally:
            pool32.close()


class LegacyAndHistorySemantics(ImportBase):
    def test_legacy_database_without_external_table(self):
        strip_external(self.pool)
        # Old commands keep working while the table is absent.
        self.pool.operate('acquire', 0, 'A', 5)
        self.assertEqual(self.pool.db.execute(
            "SELECT name FROM sqlite_master WHERE name='external_dhcp_claims'").fetchone(), None)
        capture = self.ack_capture([(4, ADDR[3], 10)])
        result = self.pool.import_dhcp(4, capture)
        self.assertEqual(len(result['claims']), 1)
        self.assertEqual(self.pool.db.execute(
            "SELECT name FROM sqlite_master WHERE name='external_dhcp_claims'").fetchone()[0],
            'external_dhcp_claims')

    def test_import_does_not_enable_history(self):
        strip_history(self.pool)
        self.assertEqual(self.pool.db.execute(
            "SELECT name FROM sqlite_master WHERE name='history_meta'").fetchone(), None)
        capture = self.ack_capture([(4, ADDR[3], 10)])
        self.pool.import_dhcp(8, capture)
        self.assertEqual(self.pool.db.execute(
            "SELECT name FROM sqlite_master WHERE name='history_meta'").fetchone(), None)

    def test_history_appends_one_post_state_event(self):
        self.pool.enable_history()
        self.pool.operate('acquire', 0, 'A', 30)
        before_seq = self.pool.db.execute('SELECT MAX(seq) FROM history_events').fetchone()[0]
        capture = self.ack_capture([(4, ADDR[1], 10)])
        self.pool.import_dhcp(8, capture)
        events = self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall()
        self.assertEqual(events[-1], (before_seq + 1, 8))
        # External claims do not appear as lease history changes.
        self.assertEqual(self.pool.db.execute(
            'SELECT COUNT(*) FROM history_changes WHERE seq=?', (events[-1][0],)).fetchone()[0], 0)
        # A repeated successful import still advances the clock and appends history.
        self.pool.import_dhcp(9, capture)
        self.assertEqual(self.pool.db.execute('SELECT MAX(seq) FROM history_events').fetchone()[0],
                         before_seq + 2)

    def test_history_write_failure_rolls_back_import(self):
        self.pool.enable_history()
        capture = self.ack_capture([(4, ADDR[3], 10)])
        self.pool.db.execute(
            "CREATE TRIGGER boom BEFORE INSERT ON history_events "
            "WHEN NEW.seq>=1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        before = self.snapshot()
        with self.assertRaises(sqlite3.Error):
            self.pool.import_dhcp(8, capture)
        self.assertEqual(self.snapshot(), before)
        self.pool.db.execute('DROP TRIGGER boom')


class ClockAndFailureAtomicity(ImportBase):
    def test_clock_backward_rejected_without_changes(self):
        capture = self.ack_capture([(4, ADDR[3], 10)])
        self.pool.import_dhcp(8, capture)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'clock cannot move backward'):
            self.pool.import_dhcp(7, capture)
        self.assertEqual(self.snapshot(), before)

    def test_bad_capture_preserves_database(self):
        good_path = self.ack_capture([(4, ADDR[3], 10)])
        good = good_path.read_bytes()
        self.pool.import_dhcp(5, good_path)
        before = self.snapshot()
        cases = [b'not a pcap' + b'\x00' * 20, good[:-2], b'', b'\xa1\xb2\x3c\x4d' + good[4:]]
        for raw in cases:
            target = self.write('bad.pcap', raw)
            with self.assertRaises(ValueError):
                self.pool.import_dhcp(8, target)
        self.assertEqual(self.snapshot(), before)

    def test_bad_checksums_reject_whole_import(self):
        message = dhcp_message(ADDR[3], 10, options=standard_options(10))
        # A nonzero but incorrect UDP checksum (zero would be legal).
        bad_segment = bytearray(udp_segment(message))
        bad_segment[6] = 0xFF
        bad_udp = ethernet_frame(bytes(bad_segment), 1)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, self.write('udp.pcap', pcap_file([(4, bad_udp)])))
        bad_ip = ethernet_frame(udp_segment(message), 2, bad_checksum=True)
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, self.write('ip.pcap', pcap_file([(4, bad_ip)])))
        self.assertEqual(self.snapshot(), before)

    def test_half_packet_rejected_atomically(self):
        # A complete datagram plus a second datagram whose final fragment is
        # missing: the good fact must not be persisted either.
        good = ethernet_frame(
            udp_segment(dhcp_message(ADDR[4], 10, options=standard_options(10))), 1)
        segment = udp_segment(dhcp_message(ADDR[5], 10, options=standard_options(10)))
        half = fragment_datagram(segment, 2, [48])[0]
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, self.write('half.pcap', pcap_file([(4, good), (4, half)])))
        self.assertEqual(self.snapshot(), before)

    def test_non_target_frames_ignored_but_capture_commits(self):
        dhcp_frame = ethernet_frame(
            udp_segment(dhcp_message(ADDR[3], 10, options=standard_options(10))), 1)
        arp = (b'\x00' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0806) + b'\x00' * 42)
        tcp = ethernet_frame(b'\x00' * 40, 2, protocol=6)
        raw = pcap_file([(4, arp), (4, tcp), (4, dhcp_frame)])
        result = self.pool.import_dhcp(8, self.write('mixed.pcap', raw))
        self.assertEqual([c['address'] for c in result['claims']], ['192.0.2.3'])

    def test_duplicate_required_option_rejects_import(self):
        bad_options = (b'\x35\x01\x05\x35\x01\x05'
                       + b'\x33\x04' + struct.pack('!I', 10)
                       + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER) + b'\xff')
        message = dhcp_message(ADDR[3], 10, options=bad_options)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.pool.import_dhcp(8, self.write('dup.pcap',
                                                pcap_file([(4, ethernet_frame(udp_segment(message), 3))])))
        self.assertEqual(self.snapshot(), before)

    def test_big_endian_capture_imports(self):
        capture = self.write('be.pcap', ack_facts_capture([(4, ADDR[3], 10)], endian='>'))
        result = self.pool.import_dhcp(8, capture)
        self.assertEqual([c['address'] for c in result['claims']], ['192.0.2.3'])

    def test_file_too_large_rejected(self):
        oversized = b'\xa1\xb2\xc3\xd4' + b'\x00' * 20 + b'\x00' * (8_000_001 - 24)
        target = self.write('big.pcap', oversized)
        with self.assertRaisesRegex(ValueError, '8 MB'):
            self.pool.import_dhcp(8, target)


class Serialisation(ImportBase):
    def test_two_connections_see_single_commit_order(self):
        # A barrier makes the two connections reach BEGIN IMMEDIATE together;
        # SQLite serialises them so allocation can never observe a window in
        # which the import's claims are half-present or absent.  Either serial
        # order is legal, but the committed state must match exactly one.
        capture = self.ack_capture([(4, ADDR[1], 20), (4, ADDR[2], 20)])
        barrier = __import__('threading').Barrier(2)

        def do_import(_):
            pool = Pool(self.path)
            try:
                barrier.wait()
                return pool.import_dhcp(8, capture)
            finally:
                pool.close()

        def do_acquire(_):
            pool = Pool(self.path)
            try:
                barrier.wait()
                return pool.operate('acquire', 8, 'C', 5)
            finally:
                pool.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(do_import, 0), executor.submit(do_acquire, 1)]
            results = [future.result() for future in futures]
        leases = {client: address for client, address, expires
                  in self.pool.db.execute('SELECT client,address,expires FROM leases')}
        import_result = next(r for r in results if 'claims' in r)
        self.assertEqual(len(import_result['claims']), 2)
        # Exactly one of the two serial orders is reflected in the final state.
        if leases['C'] in (ADDR[1], ADDR[2]):
            # Acquire committed first: C took a now-externally claimed address,
            # and the import reports that overlap as a conflict without evicting C.
            self.assertEqual({c['address'] for c in import_result['conflicts']},
                             {str(ipaddress.IPv4Address(leases['C']))})
        else:
            # Import committed first: allocation excluded both claims inside
            # its own write transaction and took the smallest free address .3.
            self.assertEqual(leases['C'], ADDR[3])
            self.assertEqual(import_result['conflicts'], [])
        # Both orders end with both facts committed and a single clock.
        self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0], 8)
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM external_dhcp_claims').fetchone()[0], 2)


class ImportCli(ImportBase):
    def run_cli(self, *extra):
        return subprocess.run([sys.executable, '-m', 'ipv4_leases.admin',
                               '--db', str(self.path), *extra],
                              capture_output=True, text=True)

    def test_cli_success_json_and_failure_exit(self):
        capture = self.ack_capture([(4, ADDR[1], 10)])
        done = self.run_cli('import-dhcp', '--now', '8', '--source', str(capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        self.assertEqual(set(payload), {'cidr', 'clock', 'leases', 'claims', 'conflicts', 'source_sha256'})
        self.assertEqual(payload['source_sha256'], hashlib.sha256(capture.read_bytes()).hexdigest())
        bad = self.write('bad.pcap', b'broken')
        failed = self.run_cli('import-dhcp', '--now', '8', '--source', str(bad))
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(failed.stdout, '')
        self.assertIn('pcap', failed.stderr)

    def test_cli_rejects_symlinks_and_same_path(self):
        capture = self.ack_capture([(4, ADDR[1], 10)])
        link = Path(self.tmp.name) / 'link.pcap'
        link.symlink_to(capture)
        failed = self.run_cli('import-dhcp', '--now', '8', '--source', str(link))
        self.assertEqual(failed.returncode, 2)
        self.assertIn('symlink', failed.stderr)
        db_link = Path(self.tmp.name) / 'dblink.sqlite'
        db_link.symlink_to(self.path)
        failed = subprocess.run([sys.executable, '-m', 'ipv4_leases.admin',
                                 '--db', str(db_link), 'import-dhcp',
                                 '--now', '8', '--source', str(capture)],
                                capture_output=True, text=True)
        self.assertEqual(failed.returncode, 2)
        self.assertIn('symlink', failed.stderr)
        failed = self.run_cli('import-dhcp', '--now', '8', '--source', str(self.path))
        self.assertEqual(failed.returncode, 2)
        self.assertIn('must differ', failed.stderr)

    def test_cli_acceptance_conflict_and_allocation(self):
        self.run_cli('acquire', '--now', '0', '--client', 'A', '--ttl', '30')
        capture = self.ack_capture([(4, ADDR[1], 10), (4, ADDR[2], 10)])
        done = self.run_cli('import-dhcp', '--now', '8', '--source', str(capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        self.assertEqual(payload['conflicts'][0]['client'], 'A')
        acquired = self.run_cli('acquire', '--now', '8', '--client', 'B', '--ttl', '20')
        self.assertEqual(json.loads(acquired.stdout)['leases'][1]['address'], '192.0.2.3')
        renewal = self.run_cli('acquire', '--now', '8', '--client', 'A', '--ttl', '5')
        self.assertEqual(renewal.returncode, 2)


if __name__ == '__main__':
    unittest.main()
