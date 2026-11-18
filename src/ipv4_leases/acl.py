"""Offline ordered ACL first-hit diffing for one IPv4 lease pool.

Two ordered policy versions (at most 64 rules each) are compared over the
exact packet domain of the pool: every usable source host of the pool times
all 2**32 IPv4 destinations times ``{tcp, udp}`` times the 65536 destination
ports.  There is no source-port dimension and no real network is touched.

Region representation and its correctness obligations
-----------------------------------------------------

A *region* is a list of mutually disjoint, normalised boxes.  A box is the
tuple ``(src_lo, src_hi, dst_lo, dst_hi, protos, port_lo, port_hi)`` where
``protos`` is a 2-bit mask (bit 0 = tcp, bit 1 = udp); every interval is
closed and integer valued.  Boxes are exact set descriptions of packets, so
the implementation never enumerates addresses, ports or packets -- all
counts are closed integer products of interval widths.

The engine has three correctness obligations, each discharged structurally:

1. **First-hit shadowing.**  Rules are applied strictly in array order.  A
   rule's effective region is its raw match region minus the union of the
   effective regions of every earlier rule (``subtract_box`` partitions the
   remainder into disjoint boxes, so earlier coverage is never counted
   twice).  What no rule catches falls into the default deny region, which
   is the full domain minus the union of the effective regions.
2. **Exact intersections.**  The two per-version partitions are mutually
   exclusive and each covers the whole domain exactly once.  Pairwise box
   intersection therefore yields mutually exclusive transition regions that
   also cover the whole domain exactly once; summing their sizes is an exact
   partition, never a comparison of allow totals.
3. **Maximal endpoints and the minimum witness.**  Box subtraction only cuts
   at the boundaries of the operands, keeping maximal endpoints, so every
   box's lower corner is a real packet of the region.  The lexicographically
   smallest packet under ``(src numeric, dst numeric, tcp before udp, port)``
   is therefore the box lower corner with the smallest ordering key; taking
   the minimum across the boxes of a region gives the region minimum witness
   without sampling.
"""
import ipaddress

from .common import ident, require

MAX_RULES = 64
PORT_COUNT = 65536
DST_SPACE = 1 << 32
PROTO_MASK = 0b11  # two protocol bits: bit 0 tcp, bit 1 udp
PROTO_TCP = 1
PROTO_UDP = 2
PROTO_ANY = PROTO_TCP | PROTO_UDP
PROTO_NAME = {PROTO_TCP: 'tcp', PROTO_UDP: 'udp'}
PROTO_INDEX = {'tcp': PROTO_TCP, 'udp': PROTO_UDP, 'any': PROTO_ANY}


def strict_cidr(value):
    """Strict IPv4 CIDR in /0../32 mapped to its inclusive integer range.

    Mirrors the routing contract: strings only, no IPv6, no host bits, and
    deliberately no pool /20 floor -- rule prefixes may cover the whole
    Internet or sit entirely outside the pool.
    """
    if not isinstance(value, str):
        raise ValueError('strict IPv4 CIDR required')
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ValueError('strict IPv4 CIDR required: ' + value) from None
    if net.version != 4:
        raise ValueError('IPv4 CIDR required: ' + value)
    return int(net.network_address), int(net.broadcast_address)


def parse_rules(rules):
    """Validate one policy array and return rules in input (priority) order.

    Each parsed rule is ``(id, action, src_lo, src_hi, dst_lo, dst_hi,
    protos, port_lo, port_hi)``.  Identifiers are unique per version only;
    the two versions may reuse ids and the array order is never reordered by
    id, prefix length or action.
    """
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError('policy must be an array of at most %d rules' % MAX_RULES)
    parsed, seen = [], set()
    for item in rules:
        require(item, 'id src dst protocol ports action')
        rule_id = ident(item['id'])
        if rule_id in seen:
            raise ValueError('duplicate rule id: ' + rule_id)
        seen.add(rule_id)
        action = item['action']
        if action not in ('allow', 'deny'):
            raise ValueError('action must be allow or deny')
        protocol = item['protocol']
        if protocol not in PROTO_INDEX:
            raise ValueError('protocol must be tcp, udp or any')
        protos = PROTO_INDEX[protocol]
        ports = item['ports']
        if not isinstance(ports, list) or len(ports) != 2:
            raise ValueError('ports must be an array of exactly two integers')
        lo, hi = ports
        # ``bool`` is an ``int`` subclass; the contract rejects booleans.
        if type(lo) is not int or type(hi) is not int:
            raise ValueError('port bounds must be integers')
        if not 0 <= lo <= hi <= 65535:
            raise ValueError('ports must satisfy 0 <= lo <= hi <= 65535')
        src_lo, src_hi = strict_cidr(item['src'])
        dst_lo, dst_hi = strict_cidr(item['dst'])
        parsed.append((rule_id, action, src_lo, src_hi, dst_lo, dst_hi,
                       protos, lo, hi))
    return parsed


def _overlap(a_lo, a_hi, b_lo, b_hi):
    lo, hi = max(a_lo, b_lo), min(a_hi, b_hi)
    return (lo, hi) if lo <= hi else None


def _outside(lo, hi, cut_lo, cut_hi):
    """The parts of closed interval ``[lo, hi]`` outside ``[cut_lo, cut_hi]``."""
    pieces = []
    if lo < cut_lo:
        pieces.append((lo, min(hi, cut_lo - 1)))
    if hi > cut_hi:
        pieces.append((max(lo, cut_hi + 1), hi))
    return pieces


def subtract_box(box, other):
    """Partition ``box \\ other`` into disjoint boxes (empty list if covered).

    Hierarchical cut on the four dimensions.  The src/dst/port remainders
    lie outside at least one cutter range, so no protocol bit is removed
    there and they keep all original proto bits; the body inside every
    cutter range is cut on the protocol dimension only.  The emitted groups
    are pairwise disjoint and their union is exactly the set difference.
    """
    s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi = box
    hit = (_overlap(s_lo, s_hi, other[0], other[1])
           and _overlap(d_lo, d_hi, other[2], other[3])
           and (protos & other[4])
           and _overlap(p_lo, p_hi, other[5], other[6]))
    if not hit:
        return [box]
    matched_protos = protos & other[4]
    # Mask the complement: Python's ``~`` yields a negative integer, which
    # would otherwise zero the conjunction instead of clearing the bits.
    remain_protos = protos & (~other[4] & PROTO_MASK)
    src_keep = _overlap(s_lo, s_hi, other[0], other[1])
    dst_keep = _overlap(d_lo, d_hi, other[2], other[3])
    port_keep = _overlap(p_lo, p_hi, other[5], other[6])
    result = []
    # Dimensional remainders are outside the cutter's ranges in at least one
    # address/port dimension, so the cutter cannot remove any protocol there:
    # they keep every proto bit of the original box.  The groups are
    # disjoint because each constrains one more dimension to the inside.
    for src in _outside(s_lo, s_hi, other[0], other[1]):
        result.append((src[0], src[1], d_lo, d_hi, protos, p_lo, p_hi))
    for dst in _outside(d_lo, d_hi, other[2], other[3]):
        result.append((src_keep[0], src_keep[1], dst[0], dst[1],
                       protos, p_lo, p_hi))
    for port in _outside(p_lo, p_hi, other[5], other[6]):
        result.append((src_keep[0], src_keep[1], dst_keep[0], dst_keep[1],
                       protos, port[0], port[1]))
    # Inside all cutter ranges: only the matched proto bits are removed, so
    # the unmatched proto bits survive on the whole inside body.
    if remain_protos:
        result.append((src_keep[0], src_keep[1], dst_keep[0], dst_keep[1],
                       remain_protos, port_keep[0], port_keep[1]))
    return result


def subtract_region(region, cutter):
    """Return ``region`` minus the union of the disjoint boxes in ``cutter``."""
    out = list(region)
    for box in cutter:
        updated = []
        for part in out:
            updated.extend(subtract_box(part, box))
        # Normalising per cut keeps the partition compact: the cutter boxes
        # are disjoint, so re-merging after each cut never changes the set.
        out = normalize(updated)
    return out


def _try_merge(one, two):
    """Merge two boxes equal in every dimension but one touching range.

    A merge is only valid when all three non-merging dimensions are exactly
    identical and the merging ranges touch (one ends immediately before the
    other starts).  Explicit preconditions prevent two boxes that merely
    touch on one dimension but differ elsewhere from collapsing into a box
    covering packets neither input contained.
    """
    s1l, s1h, d1l, d1h, pr1, p1l, p1h = one
    s2l, s2h, d2l, d2h, pr2, p2l, p2h = two
    if pr1 != pr2:
        return None
    if d1l == d2l and d1h == d2h and p1l == p2l and p1h == p2h:
        if s1h + 1 == s2l:
            return (s1l, s2h, d1l, d1h, pr1, p1l, p1h)
        if s2h + 1 == s1l:
            return (s2l, s1h, d1l, d1h, pr1, p1l, p1h)
    if s1l == s2l and s1h == s2h and p1l == p2l and p1h == p2h:
        if d1h + 1 == d2l:
            return (s1l, s1h, d1l, d2h, pr1, p1l, p1h)
        if d2h + 1 == d1l:
            return (s1l, s1h, d2l, d1h, pr1, p1l, p1h)
    if s1l == s2l and s1h == s2h and d1l == d2l and d1h == d2h:
        if p1h + 1 == p2l:
            return (s1l, s1h, d1l, d1h, pr1, p1l, p2h)
        if p2h + 1 == p1l:
            return (s1l, s1h, d1l, d1h, pr1, p2l, p1h)
    return None


def normalize(region):
    """Deduplicate and merge touching equal boxes to a fixed point.

    The inputs are already disjoint, so only identical duplicates (created by
    separate subtractions) and adjacent boxes with identical remaining
    dimensions are merged.  The output stays a disjoint exact partition.
    """
    boxes = list(region)
    while True:
        unique = list(dict.fromkeys(boxes))
        merged_any = False
        out = []
        while unique:
            box = unique.pop(0)
            for index, other in enumerate(unique):
                joined = _try_merge(box, other)
                if joined is not None:
                    box = joined
                    unique.pop(index)
                    merged_any = True
            out.append(box)
        if not merged_any:
            return out
        boxes = out


def first_hit_partition(parsed, domain):
    """Per-rule raw/effective regions plus the default deny region.

    Rules are walked in input order; each effective region is the raw match
    box minus all earlier effective regions, which is exactly the packet set
    for which this rule is the first matching rule.
    """
    covered = []
    entries = []
    for rule in parsed:
        (_id, action, s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi) = rule
        if s_lo > s_hi:
            # Rule sources never touch a pool host: retained (with zero
            # coverage) in its input position and excluded from the cover
            # partition so an inverted box can never cut another region.
            entries.append({'rule': rule, 'raw': None, 'effective': []})
            continue
        raw = (s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi)
        effective = subtract_region([raw], covered) if covered else [raw]
        entries.append({'rule': rule, 'raw': raw, 'effective': effective})
        covered = normalize(covered + effective)
    default = subtract_region([domain], covered)
    return entries, default


def intersect_boxes(one, two):
    """Intersection of two boxes, or ``None`` when they are disjoint."""
    src = _overlap(one[0], one[1], two[0], two[1])
    dst = _overlap(one[2], one[3], two[2], two[3])
    protos = one[4] & two[4]
    port = _overlap(one[5], one[6], two[5], two[6])
    if not src or not dst or not protos or not port:
        return None
    return (src[0], src[1], dst[0], dst[1], protos, port[0], port[1])


def box_volume(box):
    return ((box[1] - box[0] + 1) * (box[3] - box[2] + 1)
            * bin(box[4]).count('1') * (box[6] - box[5] + 1))


def region_volume(region):
    return sum(box_volume(box) for box in region)


def box_witness(box):
    """The minimum packet ``(src, dst, proto, port)`` contained in ``box``."""
    s_lo, _s_hi, d_lo, _d_hi, protos, p_lo, _p_hi = box
    proto = PROTO_TCP if protos & PROTO_TCP else PROTO_UDP
    return (s_lo, d_lo, proto, p_lo)


def _witness_order(packet):
    src, dst, proto, port = packet
    return (src, dst, 0 if proto == PROTO_TCP else 1, port)


def transitions(before_entries, before_default, after_entries, after_default):
    """Intersect the two first-hit partitions into ``(pair, volume, witness)``.

    The per-version partitions are mutually exclusive and each covers the
    whole domain, so the pairwise intersections are non-empty transition
    regions covering the domain exactly once.
    """
    before_groups = [(entry['rule'], entry['effective']) for entry in before_entries]
    before_groups.append((None, before_default))
    after_groups = [(entry['rule'], entry['effective']) for entry in after_entries]
    after_groups.append((None, after_default))
    totals = {}
    witnesses = {}
    for before_rule, before_region in before_groups:
        for after_rule, after_region in after_groups:
            volume = 0
            best = None
            for left in before_region:
                for right in after_region:
                    common = intersect_boxes(left, right)
                    if common is None:
                        continue
                    volume += box_volume(common)
                    packet = box_witness(common)
                    if best is None or _witness_order(packet) < _witness_order(best):
                        best = packet
            if volume:
                key = (before_rule, after_rule)
                totals[key] = totals.get(key, 0) + volume
                if key not in witnesses or _witness_order(best) < _witness_order(witnesses[key]):
                    witnesses[key] = best
    return totals, witnesses


def _rule_identity(rule):
    return None if rule is None else rule[0]


def _rule_action(rule):
    return 'deny' if rule is None else rule[1]


def build_report(cidr, clock, before_raw, after_raw):
    """Compute the complete ACL diff report for one initialised pool.

    ``cidr``/``clock`` are the only database-side inputs; leases, external
    occupancy and history are deliberately never consulted.
    """
    net = ipaddress.ip_network(cidr, strict=True)
    from .reconcile import pool_bounds
    src_lo, src_hi = pool_bounds(net)
    host_count = src_hi - src_lo + 1
    total_packets = host_count * DST_SPACE * 2 * PORT_COUNT
    domain = (src_lo, src_hi, 0, DST_SPACE - 1, PROTO_ANY, 0, 65535)

    before_parsed = parse_rules(before_raw)
    after_parsed = parse_rules(after_raw)

    def clip(parsed):
        """Clip every rule source range to the pool's usable hosts.

        Rule prefixes legitimately extend outside the pool (even /0), but
        matching packets only exist for pool source hosts, so all raw boxes
        are intersected with the source domain.  A rule fully outside the
        pool keeps its place in the report with zero coverage.
        """
        clipped = []
        for rule in parsed:
            (_id, action, s_lo, s_hi, d_lo, d_hi, protos, p_lo, p_hi) = rule
            s_lo, s_hi = max(s_lo, src_lo), min(s_hi, src_hi)
            clipped.append((_id, action, s_lo, s_hi, d_lo, d_hi,
                            protos, p_lo, p_hi))
        return clipped

    before_parsed = clip(before_parsed)
    after_parsed = clip(after_parsed)
    before_entries, before_default = first_hit_partition(before_parsed, domain)
    after_entries, after_default = first_hit_partition(after_parsed, domain)

    def usage(entries, default_region):
        rows = []
        for entry in entries:
            rule = entry['rule']
            raw_count = 0 if entry['raw'] is None else box_volume(entry['raw'])
            effective_count = region_volume(entry['effective'])
            rows.append({'id': rule[0], 'action': rule[1],
                         'raw_packets': raw_count,
                         'effective_packets': effective_count,
                         'shadowed_packets': raw_count - effective_count})
        default_effective = region_volume(default_region)
        rows.append({'id': None, 'action': 'deny',
                     'raw_packets': total_packets,
                     'effective_packets': default_effective,
                     'shadowed_packets': total_packets - default_effective})
        return rows

    before_usage = usage(before_entries, before_default)
    after_usage = usage(after_entries, after_default)

    totals, witnesses = transitions(
        before_entries, before_default, after_entries, after_default)

    def sort_key(item):
        (before_rule, after_rule), _volume = item
        before_id = _rule_identity(before_rule)
        after_id = _rule_identity(after_rule)
        # Python string order within each dimension; ``null`` ranks after
        # every string (and after the other null), so use empty string for
        # real ids and a sentinel larger than any string for null.
        return (1 if before_id is None else 0, before_id or '',
                1 if after_id is None else 0, after_id or '')

    newly_allowed = newly_denied = 0
    transition_rows = []
    for key, volume in sorted(totals.items(), key=sort_key):
        before_rule, after_rule = key
        before_action = _rule_action(before_rule)
        after_action = _rule_action(after_rule)
        if before_action == 'deny' and after_action == 'allow':
            newly_allowed += volume
        elif before_action == 'allow' and after_action == 'deny':
            newly_denied += volume
        src, dst, proto, port = witnesses[key]
        transition_rows.append({
            'before_rule': _rule_identity(before_rule),
            'after_rule': _rule_identity(after_rule),
            'before_action': before_action,
            'after_action': after_action,
            'packets': volume,
            'witness': {'src': str(ipaddress.IPv4Address(src)),
                        'dst': str(ipaddress.IPv4Address(dst)),
                        'protocol': PROTO_NAME[proto],
                        'port': port}})

    return {'cidr': str(net), 'clock': clock,
            'total_packets': total_packets,
            'newly_allowed': newly_allowed,
            'newly_denied': newly_denied,
            'before': before_usage,
            'after': after_usage,
            'transitions': transition_rows}
