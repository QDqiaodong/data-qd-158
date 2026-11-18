"""Offline DHCPACK extraction from classic libpcap files.

The parser is deliberately self-contained and uses only the Python standard
library.  It understands the classic PCAP v2.4 container (microsecond
timestamps, big or little endian, Ethernet linktype only) and turns valid
DHCPACK messages carried in UDP/IPv4 (with full IPv4 fragment reassembly)
into bounded external-address facts.  It never opens a socket.

Every structural violation raises :class:`ValueError`; a failure rejects the
whole capture, because callers only persist facts after *all* datagrams in
the file have been validated.
"""
import struct

MAX_CAPTURE_BYTES = 8_000_000
MAX_SNAPLEN = 262_144
MAX_IP_PAYLOAD = 65_515  # 65535 maximum IP total length minus the 20-byte header
DHCP_MAGIC = 0x63825363
DHCP_MIN_BYTES = 240
OPTION_PAD = 0
OPTION_OVERLOAD = 52
OPTION_MSG_TYPE = 53
OPTION_LEASE_TIME = 51
OPTION_SERVER_ID = 54
OPTION_END = 255
MSG_ACK = 5

# On-dik magic byte sequences: a1b2c3d4 precedes big-endian fields and
# d4c3b2a1 precedes little-endian fields.  The nanosecond variants share the
# same byte-order rule and are explicitly rejected.
_MAGIC_BIG = b'\xa1\xb2\xc3\xd4'
_MAGIC_LITTLE = b'\xd4\xc3\xb2\xa1'
_MAGIC_NANO_BIG = b'\xa1\xb2\x3c\x4d'
_MAGIC_NANO_LITTLE = b'\x4d\x3c\xb2\xa1'


class PcapError(ValueError):
    """Raised for any malformed or unsupported capture content."""


def _ones_complement_sum(data):
    if len(data) & 1:
        data = data + b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _ip_checksum_ok(header):
    return _ones_complement_sum(header) == 0xFFFF


def _udp_checksum_ok(src, dst, udp_length, segment):
    pseudo = struct.pack('!IIBBH', src, dst, 0, 17, udp_length)
    return _ones_complement_sum(pseudo + segment) == 0xFFFF


def _parse_pcap_container(raw, now):
    """Return validated ``(ts_sec, frame)`` records for the whole capture."""
    if len(raw) < 24:
        raise PcapError('pcap global header truncated')
    magic = raw[:4]
    if magic in (_MAGIC_NANO_BIG, _MAGIC_NANO_LITTLE):
        raise PcapError('nanosecond pcap format is not supported')
    # The on-disk byte order of the magic selects the container endianness.
    if magic == _MAGIC_BIG:
        endian = '>'
    elif magic == _MAGIC_LITTLE:
        endian = '<'
    else:
        raise PcapError('bad pcap magic; only classic microsecond PCAP v2.4 is supported')
    major, minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
        endian + 'HHiIII', raw[4:24])
    if (major, minor) != (2, 4):
        raise PcapError('unsupported pcap version %d.%d; only 2.4 is supported' % (major, minor))
    if not 1 <= snaplen <= MAX_SNAPLEN:
        raise PcapError('pcap snaplen outside 1..262144')
    if network != 1:
        raise PcapError('unsupported linktype %d; only Ethernet (1) is supported' % network)
    offset = 24
    records = []
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise PcapError('pcap record header truncated')
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + 'IIII', raw[offset:offset + 16])
        if not 0 <= ts_usec <= 999_999:
            raise PcapError('pcap record microseconds outside 0..999999')
        if not 0 <= ts_sec <= now:
            raise PcapError('pcap record seconds outside 0..now')
        if incl_len == 0 or incl_len != orig_len:
            raise PcapError('pcap record requires 0 < incl_len == orig_len')
        if incl_len > snaplen:
            raise PcapError('pcap record exceeds snaplen')
        end = offset + 16 + incl_len
        if end > len(raw):
            raise PcapError('pcap record data truncated')
        records.append((ts_sec, raw[offset + 16:end]))
        offset = end
    if offset != len(raw):  # pragma: no cover - loop invariant guard
        raise PcapError('pcap record boundary violated')
    return records


def _parse_ipv4_frame(frame):
    """Return a validated UDP IPv4 fragment descriptor, or ``None`` to skip."""
    if len(frame) < 14:
        raise PcapError('frame shorter than 14-byte Ethernet header')
    ethertype = struct.unpack('!H', frame[12:14])[0]
    if ethertype != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        raise PcapError('IPv4 header truncated')
    version_ihl = ip[0]
    if version_ihl >> 4 != 4 or (version_ihl & 0x0F) != 5:
        raise PcapError('IPv4 frames must have version=4 and IHL=5')
    total_length = struct.unpack('!H', ip[2:4])[0]
    if not 20 <= total_length <= 65535:
        raise PcapError('IPv4 total_length outside 20..65535')
    if total_length > len(ip):
        raise PcapError('IPv4 total_length exceeds captured bytes')
    if not _ip_checksum_ok(ip[:20]):
        raise PcapError('IPv4 header checksum incorrect')
    flags_byte, offset_byte = ip[6], ip[7]
    reserved, df, mf = (flags_byte >> 7) & 1, (flags_byte >> 6) & 1, (flags_byte >> 5) & 1
    fragment_offset = ((flags_byte & 0x1F) << 8) | offset_byte
    if reserved:
        raise PcapError('IPv4 reserved flag must be zero')
    if df and (mf or fragment_offset):
        raise PcapError('DF must not combine with MF or a nonzero fragment offset')
    protocol = ip[9]
    if protocol != 17:
        return None
    identification = struct.unpack('!H', ip[4:6])[0]
    src = struct.unpack('!I', ip[12:16])[0]
    dst = struct.unpack('!I', ip[16:20])[0]
    payload = ip[20:total_length]  # Ethernet padding beyond total_length is ignored
    if not payload:
        raise PcapError('IPv4 fragment payload must be non-empty')
    if mf and len(payload) % 8:
        raise PcapError('MF fragment payload length must be a multiple of 8')
    byte_offset = fragment_offset * 8
    if byte_offset + len(payload) > MAX_IP_PAYLOAD:
        raise PcapError('IPv4 reassembled payload exceeds 65515 bytes')
    return (src, dst, protocol, identification, byte_offset, payload, mf)


class _Reassembly:
    """Cross-frame reassembly state for one (src,dst,protocol,id) datagram."""

    def __init__(self):
        self.total = None
        self.buffer = bytearray()
        self.filled = bytearray()
        self.observed_at = None
        self.has_zero_offset = False

    def add(self, offset, data, mf, ts_sec):
        end = offset + len(data)
        if self.total is not None and end > self.total:
            raise PcapError('IPv4 fragment exceeds the final datagram length')
        if offset == 0:
            self.has_zero_offset = True
            self.observed_at = ts_sec if self.observed_at is None else min(self.observed_at, ts_sec)
        if end > len(self.buffer):
            grow = end - len(self.buffer)
            self.buffer.extend(b'\x00' * grow)
            self.filled.extend(b'\x00' * grow)
        for index, byte in enumerate(data):
            position = offset + index
            if self.filled[position]:
                if self.buffer[position] != byte:
                    raise PcapError('overlapping IPv4 fragments disagree')
            else:
                self.buffer[position] = byte
                self.filled[position] = 1
        if not mf:
            if self.total is None:
                if len(self.buffer) > end:
                    raise PcapError('final fragment contradicts an earlier fragment length')
                self.total = end
            elif self.total != end:
                raise PcapError('contradictory IPv4 final fragment lengths')

    def finish(self):
        if not self.has_zero_offset:
            raise PcapError('IPv4 datagram missing a zero-offset fragment')
        if self.total is None:
            raise PcapError('IPv4 datagram missing a final (MF=0) fragment')
        if len(self.buffer) != self.total or not all(self.filled):
            raise PcapError('IPv4 datagram has a reassembly hole')
        return bytes(self.buffer[:self.total]), self.observed_at


def _parse_tlv_region(region, allow_overload_option):
    """Decode one options region under pad/end/length TLV rules."""
    options = []
    index = 0
    while index < len(region):
        code = region[index]
        index += 1
        if code == OPTION_PAD:
            continue
        if code == OPTION_END:
            return options
        if index >= len(region):
            raise PcapError('DHCP option length byte is out of bounds')
        length = region[index]
        index += 1
        if index + length > len(region):
            raise PcapError('DHCP option value is out of bounds')
        if code == OPTION_OVERLOAD and not allow_overload_option:
            raise PcapError('DHCP option 52 may only appear in the main options')
        options.append((code, region[index:index + length]))
        index += length
    raise PcapError('DHCP options are missing the end marker')


def _single_required(options, code, length=None):
    values = [value for candidate, value in options if candidate == code]
    if len(values) != 1:
        raise PcapError('DHCP option %d must appear exactly once' % code)
    if length is not None and len(values[0]) != length:
        raise PcapError('DHCP option %d must have length %d' % (code, length))
    return values[0]


def _parse_dhcp(src, dst, segment, observed_at):
    """Validate one reassembled UDP segment; return a fact dict or ``None``."""
    if len(segment) < 8:
        raise PcapError('UDP segment shorter than 8 bytes')
    udp_length = struct.unpack('!H', segment[4:6])[0]
    if udp_length != len(segment):
        raise PcapError('UDP length does not match the reassembled datagram')
    src_port, dst_port = struct.unpack('!HH', segment[:4])
    if (src_port, dst_port) != (67, 68):
        return None
    checksum = struct.unpack('!H', segment[6:8])[0]
    if checksum and not _udp_checksum_ok(src, dst, udp_length, segment):
        raise PcapError('UDP checksum incorrect')
    message = segment[8:]
    if len(message) < DHCP_MIN_BYTES:
        raise PcapError('DHCP message must be at least 240 bytes')
    if struct.unpack('!I', message[236:240])[0] != DHCP_MAGIC:
        raise PcapError('bad DHCP magic cookie')
    main_options = _parse_tlv_region(message[240:], allow_overload_option=True)
    overload_values = [value for code, value in main_options if code == OPTION_OVERLOAD]
    if len(overload_values) > 1 or (overload_values and len(overload_values[0]) != 1):
        raise PcapError('DHCP option 52 must appear once with one byte')
    selected = list(main_options)
    if overload_values:
        overload = overload_values[0][0]
        if overload not in (1, 2, 3):
            raise PcapError('DHCP option 52 value must be 1, 2 or 3')
        file_field, sname_field = message[44:108], message[108:236]
        if overload in (1, 3):
            selected.extend(_parse_tlv_region(file_field, allow_overload_option=False))
        if overload in (2, 3):
            selected.extend(_parse_tlv_region(sname_field, allow_overload_option=False))
    msg_type = _single_required(selected, OPTION_MSG_TYPE, length=1)[0]
    if msg_type != MSG_ACK:
        return None
    op, htype, hlen = message[0], message[1], message[2]
    if (op, htype, hlen) != (2, 1, 6):
        raise PcapError('DHCPACK requires op=2, htype=1 and hlen=6')
    yiaddr = struct.unpack('!I', message[16:20])[0]
    if yiaddr == 0:
        raise PcapError('DHCPACK yiaddr must be nonzero')
    lease_bytes = _single_required(selected, OPTION_LEASE_TIME, length=4)
    ttl = struct.unpack('!I', lease_bytes)[0]
    if not 1 <= ttl <= 10 ** 9:
        raise PcapError('DHCP option 51 TTL must be 1..10^9 seconds')
    server_bytes = _single_required(selected, OPTION_SERVER_ID, length=4)
    server = struct.unpack('!I', server_bytes)[0]
    if server == 0:
        raise PcapError('DHCP option 54 server identifier must be nonzero')
    mac = ':'.join('%02x' % byte for byte in message[28:34])
    return {'server': server, 'mac': mac, 'address': yiaddr,
            'observed_at': observed_at, 'ttl': ttl,
            'expires': observed_at + ttl}


def parse_capture(raw, now):
    """Parse a complete capture into validated, de-duplicated DHCP facts.

    ``raw`` is the exact capture byte string; ``now`` bounds every record
    timestamp.  All frames are parsed and every IPv4 group is reassembled and
    validated before any fact is returned, so a late contradiction rejects the
    whole import.  Non-DHCP traffic, non-ACK messages and malformed-free
    ignored frames simply produce no facts; structural violations raise
    :class:`PcapError`.
    """
    if not isinstance(now, int) or type(now) is not int or not 0 <= now <= 10 ** 12:
        raise PcapError('now must be an integer tick in 0..10^12')
    records = _parse_pcap_container(raw, now)
    groups = {}
    for ts_sec, frame in records:
        descriptor = _parse_ipv4_frame(frame)
        if descriptor is None:
            continue
        src, dst, protocol, identification, offset, payload, mf = descriptor
        key = (src, dst, protocol, identification)
        if key not in groups:
            groups[key] = _Reassembly()
        groups[key].add(offset, payload, mf, ts_sec)
    facts = {}
    for (src, dst, _protocol, _identification), group in groups.items():
        datagram, observed_at = group.finish()
        fact = _parse_dhcp(src, dst, datagram, observed_at)
        if fact is None:
            continue
        identity = (fact['server'], fact['mac'], fact['address'],
                    fact['observed_at'], fact['ttl'])
        facts[identity] = fact
    return list(facts.values())
