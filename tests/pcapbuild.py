"""Synthetic classic-PCAP / IPv4 / UDP / DHCP byte builders for tests.

Everything here is hand-built from raw bytes with the standard library only;
no real network is touched.  The builders deliberately expose the knobs the
specification validates (fragment order, overlaps, checksums, options,
overload regions, container endianness and corruption points).
"""
import struct

ETH_HEADER = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + struct.pack('!H', 0x0800)
DEFAULT_SRC = 0x0A000001
DEFAULT_DST = 0x0A000002
DEFAULT_SERVER = 0x0A000009
DEFAULT_MAC = b'\xaa\xbb\xcc\xdd\xee\xff'


def ones_complement_checksum(data):
    if len(data) & 1:
        data = data + b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def dhcp_message(yiaddr, ttl, server=DEFAULT_SERVER, mac=DEFAULT_MAC, mtype=5,
                 op=2, htype=1, hlen=6, options=b'', magic=0x63825363, size=300,
                 file_field=b'', sname_field=b''):
    """Build a BOOTP/DHCP message with separate file/sname override regions."""
    if size < 240:
        raise ValueError('DHCP message must be at least 240 bytes')
    msg = bytearray(size)
    msg[0], msg[1], msg[2] = op, htype, hlen
    struct.pack_into('!I', msg, 16, yiaddr)
    msg[28:34] = mac
    if file_field:
        msg[44:44 + len(file_field)] = file_field
    if sname_field:
        msg[108:108 + len(sname_field)] = sname_field
    struct.pack_into('!I', msg, 236, magic)
    msg[240:240 + len(options)] = options
    return bytes(msg)


def standard_options(ttl, server=DEFAULT_SERVER, mtype=5, tail=b''):
    return (b'\x35\x01' + bytes([mtype])
            + b'\x33\x04' + struct.pack('!I', ttl)
            + b'\x36\x04' + struct.pack('!I', server)
            + tail + b'\xff')


def udp_segment(payload, src=DEFAULT_SRC, dst=DEFAULT_DST, bad_checksum=False,
                src_port=67, dst_port=68, length_override=None):
    length = length_override if length_override is not None else 8 + len(payload)
    segment = struct.pack('!HHH', src_port, dst_port, length) + b'\x00\x00' + payload
    if not bad_checksum:
        pseudo = struct.pack('!IIBBH', src, dst, 0, 17, length)
        checksum = ones_complement_checksum(pseudo + segment)
        segment = segment[:6] + struct.pack('!H', checksum) + segment[8:]
    return segment


def ip_header(payload_length, ident, src=DEFAULT_SRC, dst=DEFAULT_DST,
              mf=False, fragment_offset=0, df=False, reserved=False,
              protocol=17, bad_checksum=False, total_length_override=None):
    """``fragment_offset`` is the raw 13-bit IP field (8-byte units)."""
    total = total_length_override if total_length_override is not None else 20 + payload_length
    # High 3 bits are reserved/DF/MF, low 13 bits the fragment offset.
    flags = (1 if reserved else 0) << 2 | (1 if df else 0) << 1 | (1 if mf else 0)
    flags_offset = (flags << 13) | fragment_offset
    header = struct.pack('!BBHHHBBHII', 0x45, 0, total, ident, flags_offset,
                         64, protocol, 0, src, dst)
    checksum = ones_complement_checksum(header)
    if bad_checksum:
        checksum ^= 0xFFFF
    return header[:10] + struct.pack('!H', checksum) + header[12:]


def ethernet_frame(ip_payload, ident, **header_kwargs):
    """One Ethernet frame carrying an IP fragment (or full datagram)."""
    header = ip_header(len(ip_payload), ident, **header_kwargs)
    return ETH_HEADER + header + ip_payload + b'\x00' * ((len(ip_payload) + 1) & 0)


def fragment_datagram(segment, ident, cuts, src=DEFAULT_SRC, dst=DEFAULT_DST,
                      mf_flags=None, **header_kwargs):
    """Split a UDP segment at byte offsets and return the fragment frames.

    ``cuts`` are fragment payload boundaries relative to the UDP payload.
    """
    offsets = [0] + list(cuts) + [len(segment)]
    frames = []
    count = len(offsets) - 1
    for index in range(count):
        start, end = offsets[index], offsets[index + 1]
        is_last = index == count - 1
        mf = (not is_last) if mf_flags is None else mf_flags[index]
        frames.append(ethernet_frame(
            segment[start:end], ident, src=src, dst=dst, mf=mf,
            fragment_offset=start // 8, **header_kwargs))
    return frames
def pcap_file(records, endian='<', magic_override=None, version=(2, 4),
              snaplen=65535, network=1, thiszone=0, sigfigs=0):
    """Serialize ``(ts_sec, frame)`` records into a classic PCAP byte string."""
    magic = magic_override or (b'\xa1\xb2\xc3\xd4' if endian == '>' else b'\xd4\xc3\xb2\xa1')
    header = magic + struct.pack(endian + 'HHiIII', version[0], version[1],
                                 thiszone, sigfigs, snaplen, network)
    body = b''
    for item in records:
        if isinstance(item, tuple) and len(item) == 2:
            ts_sec, frame = item
            ts_usec = 0
        else:
            ts_sec, ts_usec, frame = item
        body += struct.pack(endian + 'IIII', ts_sec, ts_usec, len(frame), len(frame)) + frame
    return header + body


def ack_facts_capture(records, endian='<', ident_start=1):
    """Convenience: records is a list of (sec, yiaddr, ttl[, server, mac])."""
    frames = []
    for index, item in enumerate(records):
        sec, yiaddr, ttl = item[0], item[1], item[2]
        server = item[3] if len(item) > 3 else DEFAULT_SERVER
        mac = item[4] if len(item) > 4 else DEFAULT_MAC
        message = dhcp_message(yiaddr, ttl, server=server, mac=mac,
                               options=standard_options(ttl, server))
        segment = udp_segment(message)
        frames.append((sec, ethernet_frame(segment, ident_start + index)))
    return pcap_file(frames, endian=endian)
