import struct, unittest
from ipv4_leases.dhcp import parse_capture, PcapError
from pcapbuild import (ack_facts_capture, dhcp_message, standard_options,
                      udp_segment, ethernet_frame, fragment_datagram,
                      pcap_file, ip_header,
                      ETH_HEADER, DEFAULT_SERVER,
                      DEFAULT_MAC)

ADDR1 = 0xC0000201  # 192.0.2.1
ADDR2 = 0xC0000202
ADDR3 = 0xC0000203
MAC2 = b'\x01\x02\x03\x04\x05\x06'
SERVER2 = 0x0A00000A


def ack(yiaddr, ttl, mtype=5, server=DEFAULT_SERVER, mac=DEFAULT_MAC, **kwargs):
    return dhcp_message(yiaddr, ttl, server=server, mac=mac, mtype=mtype,
                        options=standard_options(ttl, server, mtype), **kwargs)


class ContainerContract(unittest.TestCase):
    def test_rejects_short_and_bad_magic(self):
        for raw in (b'', b'\x00' * 23, b'xxxx' + b'\x00' * 20,
                    b'\xa1\xb2\x3c\x4d' + b'\x00' * 20,
                    b'\x4d\x3c\xb2\xa1' + b'\x00' * 20):
            with self.subTest(raw=raw[:4]):
                with self.assertRaises(PcapError):
                    parse_capture(raw, 10)

    def test_big_and_little_endian(self):
        for endian in ('<', '>'):
            with self.subTest(endian=endian):
                raw = ack_facts_capture([(4, ADDR1, 10)], endian=endian)
                facts = parse_capture(raw, 8)
                self.assertEqual(len(facts), 1)
                self.assertEqual((facts[0]['address'], facts[0]['observed_at'],
                                  facts[0]['ttl'], facts[0]['expires']),
                                 (ADDR1, 4, 10, 14))

    def test_header_field_violations(self):
        good = ack_facts_capture([(4, ADDR1, 10)])
        # bad version, snaplen bounds (0 and 262145), non-Ethernet linktype
        for patch in (lambda b: b[:4] + struct.pack('<HH', 2, 3) + b[8:],
                      lambda b: b[:16] + struct.pack('<I', 0) + b[20:],
                      lambda b: b[:16] + struct.pack('<I', 262145) + b[20:],
                      lambda b: b[:20] + struct.pack('<I', 12) + b[24:]):
            with self.subTest():
                with self.assertRaises(PcapError):
                    parse_capture(patch(good), 8)

    def test_truncated_global_and_record_headers(self):
        good = ack_facts_capture([(4, ADDR1, 10)])
        with self.assertRaises(PcapError):
            parse_capture(good[:23], 8)
        with self.assertRaises(PcapError):
            parse_capture(good[:-1], 8)  # cut record payload
        with self.assertRaises(PcapError):
            parse_capture(good[:30], 8)  # cut record header

    def test_record_invariants(self):
        frame = ethernet_frame(udp_segment(ack(ADDR1, 10)), 1)
        # usec out of range, seconds beyond now, zero incl_len, orig mismatch
        for record in (struct.pack('<IIII', 4, 1_000_000, len(frame), len(frame)) + frame,
                       struct.pack('<IIII', 9, 0, len(frame), len(frame)) + frame,
                       struct.pack('<IIII', 4, 0, 0, 0),
                       struct.pack('<IIII', 4, 0, len(frame), len(frame) - 1) + frame,
                       struct.pack('<IIII', 4, 0, 65535, 65535) + frame):
            raw = good_global() + record
            with self.subTest():
                with self.assertRaises(PcapError):
                    parse_capture(raw, 8)

    def test_snaplen_boundary_accepted(self):
        frame = ethernet_frame(udp_segment(ack(ADDR1, 10)), 1)
        raw = pcap_file([(4, frame)], snaplen=262144)
        self.assertEqual(len(parse_capture(raw, 8)), 1)

    def test_empty_capture_is_valid(self):
        self.assertEqual(parse_capture(good_global(), 8), [])


def good_global():
    return pcap_file([])


class FrameAndIpContract(unittest.TestCase):
    def _raw(self, frame, sec=4):
        return pcap_file([(sec, frame)])

    def test_short_ethernet_fails(self):
        with self.assertRaises(PcapError):
            parse_capture(self._raw(b'\x00' * 13), 8)

    def test_non_ipv4_ethertype_ignored(self):
        frame = ETH_HEADER[:12] + struct.pack('!H', 0x0806) + b'\x00' * 40
        self.assertEqual(parse_capture(self._raw(frame), 8), [])

    def test_bad_version_ihl(self):
        segment = udp_segment(ack(ADDR1, 10))
        for byte in (0x46, 0x55, 0x05):
            frame = ETH_HEADER + ip_header(len(segment), 1) + segment
            frame = frame[:14] + bytes([byte]) + frame[15:]
            with self.assertRaises(PcapError):
                parse_capture(self._raw(frame), 8)

    def test_total_length_violations(self):
        segment = udp_segment(ack(ADDR1, 10))
        # total_length too small and total_length beyond captured bytes
        small = ETH_HEADER + ip_header(len(segment), 1, total_length_override=19) + segment
        big = ETH_HEADER + ip_header(len(segment), 1, total_length_override=len(segment) + 21) + segment
        for frame in (small, big):
            with self.assertRaises(PcapError):
                parse_capture(self._raw(frame), 8)

    def test_bad_ip_checksum_fails(self):
        frame = ethernet_frame(udp_segment(ack(ADDR1, 10)), 1, bad_checksum=True)
        with self.assertRaises(PcapError):
            parse_capture(self._raw(frame), 8)

    def test_reserved_and_df_combinations(self):
        segment = udp_segment(ack(ADDR1, 10))
        with self.assertRaises(PcapError):  # reserved bit set
            parse_capture(self._raw(ethernet_frame(segment, 1, reserved=True)), 8)
        with self.assertRaises(PcapError):  # DF + MF
            parse_capture(self._raw(ethernet_frame(segment, 1, df=True, mf=True)), 8)
        with self.assertRaises(PcapError):  # DF + nonzero offset
            parse_capture(self._raw(ethernet_frame(segment, 1, df=True, fragment_offset=1)), 8)
        # Plain DF on an unfragmented datagram is fine.
        self.assertEqual(len(parse_capture(self._raw(ethernet_frame(segment, 1, df=True)), 8)), 1)

    def test_non_udp_protocol_ignored(self):
        segment = udp_segment(ack(ADDR1, 10))
        frame = ethernet_frame(segment, 1, protocol=6)
        self.assertEqual(parse_capture(self._raw(frame), 8), [])

    def test_ethernet_padding_ignored(self):
        frame = ethernet_frame(udp_segment(ack(ADDR1, 10)), 1) + b'\x00' * 12
        self.assertEqual(len(parse_capture(self._raw(frame), 8)), 1)

    def test_mf_payload_multiple_of_eight(self):
        # MF=1 fragment with non-multiple-of-8 payload length is invalid.
        segment = udp_segment(ack(ADDR1, 10))
        first = ethernet_frame(segment[:7], 1, mf=True, fragment_offset=0)
        last = ethernet_frame(segment[7:], 1, mf=False, fragment_offset=0)
        with self.assertRaises(PcapError):
            parse_capture(pcap_file([(4, first), (4, last)]), 8)


class ReassemblyContract(unittest.TestCase):
    def setUp(self):
        self.segment = udp_segment(ack(ADDR1, 10))

    def test_unfragmented_uses_same_rules(self):
        facts = parse_capture(pcap_file([(4, ethernet_frame(self.segment, 7))]), 8)
        self.assertEqual(facts[0]['observed_at'], 4)

    def test_out_of_order_interleaved_fragments(self):
        a = udp_segment(ack(ADDR1, 10))
        b = udp_segment(ack(ADDR2, 10))
        fa = fragment_datagram(a, 11, [40, 80])
        fb = fragment_datagram(b, 12, [32, 96])
        records = [(4, fa[2]), (4, fb[0]), (4, fa[0]), (5, fb[2]), (5, fa[1]), (5, fb[1])]
        facts = parse_capture(pcap_file(records), 8)
        self.assertEqual(sorted(f['address'] for f in facts), [ADDR1, ADDR2])
        self.assertEqual({f['observed_at'] for f in facts}, {4})

    def test_identical_overlapping_duplicates_accepted(self):
        frames = fragment_datagram(self.segment, 13, [48, 96])
        # Re-send the first and middle fragments byte-identically, interleaved.
        records = [(4, frames[0]), (4, frames[1]), (4, frames[0]),
                   (4, frames[2]), (4, frames[1])]
        self.assertEqual(len(parse_capture(pcap_file(records), 8)), 1)

    def test_conflicting_overlap_rejects_whole_import(self):
        frames = fragment_datagram(self.segment, 13, [48, 96])
        good_other = ethernet_frame(udp_segment(ack(ADDR2, 10)), 14)
        mutated = bytearray(frames[1])
        mutated[-1] ^= 0xFF  # flip a payload byte of an overlapping fragment
        records = [(4, good_other), (4, frames[0]), (4, bytes(mutated)), (4, frames[2])]
        with self.assertRaises(PcapError):
            parse_capture(pcap_file(records), 8)

    def test_contradictory_final_fragment(self):
        frames = fragment_datagram(self.segment, 13, [48])
        # A second final fragment claiming a different total length.
        extra = ethernet_frame(b'\x00' * 8, 13, mf=False,
                               fragment_offset=(len(self.segment) + 7) // 8)
        with self.assertRaises(PcapError):
            parse_capture(pcap_file([(4, frames[0]), (4, frames[1]), (4, extra)]), 8)

    def test_missing_hole_and_missing_final(self):
        frames = fragment_datagram(self.segment, 13, [48, 96])
        with self.assertRaises(PcapError):  # one-byte hole: drop last fragment
            parse_capture(pcap_file([(4, frames[0]), (4, frames[1])]), 8)
        with self.assertRaises(PcapError):  # no MF=0 fragment at all
            parse_capture(pcap_file([(4, frames[0])]), 8)

    def test_missing_zero_offset(self):
        frames = fragment_datagram(self.segment, 13, [48, 96])
        with self.assertRaises(PcapError):
            parse_capture(pcap_file([(4, frames[1]), (4, frames[2])]), 8)

    def test_observed_at_is_earliest_zero_offset_second(self):
        frames = fragment_datagram(self.segment, 13, [48, 96])
        repeated_zero = frames[0]
        records = [(7, frames[1]), (4, repeated_zero), (6, frames[0]), (5, frames[2])]
        facts = parse_capture(pcap_file(records), 8)
        self.assertEqual(facts[0]['observed_at'], 4)

    def test_fragment_beyond_final_length_rejected(self):
        frames = fragment_datagram(self.segment, 13, [48])
        oversized = ethernet_frame(b'\x00' * 16, 13,
                                   fragment_offset=len(self.segment) // 8 + 2)
        with self.assertRaises(PcapError):
            parse_capture(pcap_file([(4, frames[0]), (4, frames[1]), (4, oversized)]), 8)

    def test_final_fragment_arrives_first(self):
        # The MF=0 fragment fixes the total before any other fragment arrives.
        frames = fragment_datagram(self.segment, 15, [48, 120])
        records = [(4, frames[2]), (5, frames[0]), (6, frames[1])]
        facts = parse_capture(pcap_file(records), 8)
        self.assertEqual(len(facts), 1)
        # A later fragment reaching past the declared total still rejects.
        overshoot = ethernet_frame(b'X' * 40, 15,
                                   fragment_offset=len(self.segment) // 8 - 2)
        with self.assertRaises(PcapError):
            parse_capture(pcap_file([(4, frames[2]), (4, overshoot)]), 8)

    def test_same_quadruple_is_one_datagram(self):
        # Two different IP IDs interleave without cross-group contamination.
        a = udp_segment(ack(ADDR1, 10))
        b = udp_segment(ack(ADDR2, 10))
        fa = fragment_datagram(a, 21, [40])
        fb = fragment_datagram(b, 22, [40])
        facts = parse_capture(pcap_file([(4, fa[0]), (4, fb[0]), (4, fa[1]), (4, fb[1])]), 8)
        self.assertEqual(sorted(f['address'] for f in facts), [ADDR1, ADDR2])


class UdpAndDhcpContract(unittest.TestCase):
    def capture(self, segment, ident=1, **kwargs):
        return pcap_file([(4, ethernet_frame(segment, ident, **kwargs))])

    def test_udp_length_mismatch_fails(self):
        message = ack(ADDR1, 10)
        segment = udp_segment(message, length_override=8 + len(message) + 1)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(segment), 8)

    def test_zero_checksum_legal_other_ports_ignored(self):
        message = ack(ADDR1, 10)
        zero = udp_segment(message, bad_checksum=True, src_port=1067, dst_port=1068)
        self.assertEqual(parse_capture(self.capture(zero), 8), [])
        # Checksum zero is legal even for the DHCP ports.
        zero_dhcp = udp_segment(message, bad_checksum=True)
        self.assertEqual(len(parse_capture(self.capture(zero_dhcp), 8)), 1)

    def test_bad_udp_checksum_fails(self):
        message = ack(ADDR1, 10)
        segment = bytearray(udp_segment(message))
        segment[6] ^= 0xFF
        with self.assertRaises(PcapError):
            parse_capture(self.capture(bytes(segment)), 8)

    def test_short_dhcp_and_bad_cookie(self):
        short = dhcp_message(ADDR1, 10)[:239]  # below the 240-byte DHCP minimum
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(short)), 8)
        bad_cookie = dhcp_message(ADDR1, 10, magic=0xDEADBEEF)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(bad_cookie)), 8)

    def test_tlv_oob_and_missing_end(self):
        # length byte claims more than the region holds
        options = b'\x35\x01\x05\x33\x10' + b'\x00' * 4
        message = dhcp_message(ADDR1, 10, options=options)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)
        # no end marker before the fixed 300-byte region boundary
        message = dhcp_message(ADDR1, 10, options=b'\x35\x01\x05\x33\x04' + b'\x00' * 4 + b'\x36\x04' + b'\x00' * 4)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)

    def test_bytes_after_end_ignored(self):
        options = standard_options(10) + b'\x07\x04\xab\xcd\xef\x01'
        message = dhcp_message(ADDR1, 10, options=options)
        self.assertEqual(len(parse_capture(self.capture(udp_segment(message)), 8)), 1)

    def test_non_ack_ignored(self):
        for mtype in (1, 2, 3, 4, 6, 7, 8):
            message = ack(ADDR1, 10, mtype=mtype)
            self.assertEqual(parse_capture(self.capture(udp_segment(message)), 8), [], mtype)

    def test_ack_header_fields(self):
        for kwargs in (dict(op=1), dict(htype=2), dict(hlen=7)):
            message = dhcp_message(ADDR1, 10, **{**kwargs, 'options': standard_options(10)})
            with self.assertRaises(PcapError):
                parse_capture(self.capture(udp_segment(message)), 8)

    def test_zero_yiaddr_and_server_rejected(self):
        message = dhcp_message(0, 10, options=standard_options(10))
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)
        message = dhcp_message(ADDR1, 10, server=0, options=standard_options(10, server=0))
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)

    def test_ttl_bounds_and_option_lengths(self):
        bad_ttl = dhcp_message(ADDR1, 0, options=b'\x35\x01\x05\x33\x04\x00\x00\x00\x00'
                               + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER) + b'\xff')
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(bad_ttl)), 8)
        short_51 = dhcp_message(ADDR1, 10, options=b'\x35\x01\x05\x33\x03\x00\x00\x0a'
                                + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER) + b'\xff')
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(short_51)), 8)

    def test_duplicate_required_options_reject(self):
        duplicated = (b'\x35\x01\x05' * 2
                      + b'\x33\x04' + struct.pack('!I', 10)
                      + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER) + b'\xff')
        message = dhcp_message(ADDR1, 10, options=duplicated)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)

    def test_missing_required_option_rejects(self):
        no_server = b'\x35\x01\x05\x33\x04' + struct.pack('!I', 10) + b'\xff'
        message = dhcp_message(ADDR1, 10, options=no_server)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)

    def test_mac_canonical_lowercase_colon(self):
        message = ack(ADDR1, 10, mac=MAC2)
        facts = parse_capture(self.capture(udp_segment(message)), 8)
        self.assertEqual(facts[0]['mac'], '01:02:03:04:05:06')

    def test_two_servers_and_macs_keep_independent_facts(self):
        frames = [
            (4, ethernet_frame(udp_segment(ack(ADDR1, 10, server=DEFAULT_SERVER, mac=DEFAULT_MAC)), 1)),
            (4, ethernet_frame(udp_segment(ack(ADDR1, 10, server=SERVER2, mac=MAC2)), 2)),
        ]
        facts = parse_capture(pcap_file(frames), 8)
        self.assertEqual(len(facts), 2)
        self.assertEqual(sorted((f['server'], f['mac']) for f in facts),
                         sorted([(DEFAULT_SERVER, 'aa:bb:cc:dd:ee:ff'), (SERVER2, '01:02:03:04:05:06')]))

    def test_duplicate_five_tuple_dedupes_even_from_different_paths(self):
        raw = ack_facts_capture([(4, ADDR1, 10), (4, ADDR1, 10)])
        facts = parse_capture(raw, 8)
        self.assertEqual(len(facts), 1)

    def test_expired_ack_still_parsed_but_marked(self):
        # observed_at=4 + ttl=2 -> expires=6; parser keeps it, pool filters at now.
        facts = parse_capture(ack_facts_capture([(4, ADDR1, 2)]), 8)
        self.assertEqual(facts[0]['expires'], 6)

    def test_option_overload_file_and_sname(self):
        def region_with(option_code):
            value = struct.pack('!I', 10) if option_code == 51 else struct.pack('!I', DEFAULT_SERVER)
            return bytes([option_code, 4]) + value + b'\xff'
        cases = [
            (1, {'file_field': b'\x33\x04' + struct.pack('!I', 10)
                 + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER) + b'\xff'}),
            (2, {'sname_field': b'\x33\x04' + struct.pack('!I', 10)
                 + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER) + b'\xff'}),
            # Both regions selected: split the required options across them.
            (3, {'file_field': region_with(51), 'sname_field': region_with(54)}),
        ]
        for overload, kwargs in cases:
            options = b'\x35\x01\x05\x34\x01' + bytes([overload]) + b'\xff'
            message = dhcp_message(ADDR1, 10, options=options, **kwargs)
            facts = parse_capture(self.capture(udp_segment(message)), 8)
            self.assertEqual(len(facts), 1, overload)
            self.assertEqual(facts[0]['ttl'], 10)

    def test_overload_repeated_and_illegal_value(self):
        bad = b'\x35\x01\x05\x34\x01\x01\x34\x01\x01\xff'
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(dhcp_message(ADDR1, 10, options=bad))), 8)
        bad_value = b'\x35\x01\x05\x34\x01\x04\xff'
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(dhcp_message(ADDR1, 10, options=bad_value))), 8)

    def test_overload_52_inside_region_rejected(self):
        # Main option 52 selects the file field, which itself illegally
        # contains another option 52.
        region = b'\x34\x01\x01\xff'
        options = (b'\x35\x01\x05\x34\x01\x01\xff'
                   + b'\x33\x04' + struct.pack('!I', 10)
                   + b'\x36\x04' + struct.pack('!I', DEFAULT_SERVER))
        message = dhcp_message(ADDR1, 10, options=options, file_field=region)
        with self.assertRaises(PcapError):
            parse_capture(self.capture(udp_segment(message)), 8)


if __name__ == '__main__':
    unittest.main()
