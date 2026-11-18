"""Offline attribution of sampled flow intervals to historical leaseholders.

The attribution engine only reads the append-only history written by
:class:`ipv4_leases.pool.Pool` after history has been enabled.  It never
consults the live ``leases`` table (except through the baseline snapshot
stored in the history) and never mutates the database.
"""
import ipaddress
from bisect import bisect_right

from .common import ident, number, require
from .reconcile import pool_bounds

MAX_FLOWS = 10000
MAX_TIME = 10 ** 12
MAX_BYTES = 10 ** 18


def parse_flows(flows, clock):
    """Validate the strict ``flows`` array against the read clock.

    The returned list keeps the original address spelling and the integer
    address used for history lookups.
    """
    if not isinstance(flows, list) or len(flows) > MAX_FLOWS:
        raise ValueError('flows must be an array of at most 10000 items')
    parsed, seen = [], set()
    for item in flows:
        require(item, 'id address start end bytes')
        flow_id = ident(item['id'])
        if flow_id in seen:
            raise ValueError('duplicate flow id: ' + flow_id)
        seen.add(flow_id)
        address = item['address']
        if not isinstance(address, str):
            raise ValueError('strict IPv4 address required')
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            raise ValueError('strict IPv4 address required: ' + str(address)) from None
        start = number(item['start'], 0, MAX_TIME)
        end = number(item['end'], 0, MAX_TIME)
        if start >= end:
            raise ValueError('flow start must be before its end')
        if end > clock:
            raise ValueError('flow end exceeds the committed clock')
        byte_count = number(item['bytes'], 0, MAX_BYTES)
        parsed.append({'id': flow_id, 'address': address, 'ip': int(ip),
                       'start': start, 'end': end, 'bytes': byte_count})
    return parsed


def _ticks_for_address(db, address, snapshot_seq):
    """Final per-tick ownership change for one address, in commit order.

    Each row is ``(now, client, expires)``.  ``client is None`` means the
    address became free.  Multiple commits at the same tick are collapsed to
    the last committed (largest seq) state, exactly as the half-open tick
    rule requires.
    """
    rows = db.execute(
        'SELECT e.now, c.client, c.expires, c.seq '
        'FROM history_changes c JOIN history_events e ON e.seq=c.seq '
        'WHERE c.address=? AND c.seq<=? ORDER BY c.seq',
        (address, snapshot_seq)).fetchall()
    ticks = []
    for now, client, expires, _seq in rows:
        if ticks and ticks[-1][0] == now:
            ticks[-1] = (now, client, expires)
        else:
            ticks.append((now, client, expires))
    return ticks


def _ownership_segments(ticks, start, end):
    """Maximal owned/free segments on ``[start, end)`` for one address."""
    if start >= end:
        return []
    boundaries = {start, end}
    for now, client, expires in ticks:
        if start < now < end:
            boundaries.add(now)
        # Obsolete expiry boundaries may split an interval unnecessarily;
        # adjacent equal segments are merged below, so the result stays
        # maximal.  Including them is what makes shortened renewals exact.
        if client is not None and expires is not None and start < expires < end:
            boundaries.add(expires)
    bounds = sorted(boundaries)
    nows = [tick[0] for tick in ticks]
    index = bisect_right(nows, start) - 1
    result = []
    for left, right in zip(bounds, bounds[1:]):
        while index + 1 < len(ticks) and ticks[index + 1][0] <= left:
            index += 1
        state = ticks[index] if index >= 0 else None
        if state is not None and state[1] is not None and state[2] is not None and state[2] > left:
            status, client = 'owned', state[1]
        else:
            status, client = 'free', None
        if result and result[-1][2] == status and result[-1][3] == client:
            result[-1] = (result[-1][0], right, status, client)
        else:
            result.append((left, right, status, client))
    return result


def _flow_segments(coverage_start, usable, ip, ticks, start, end):
    """Full, ordered, non-overlapping segment list covering ``[start, end)``."""
    if not usable[0] <= ip <= usable[1]:
        return [(start, end, 'outside_pool', None)]
    result, cursor = [], start
    if start < coverage_start:
        unknown_end = min(coverage_start, end)
        result.append((start, unknown_end, 'unknown', None))
        cursor = unknown_end
    if cursor < end:
        result.extend(_ownership_segments(ticks, cursor, end))
    return result


def _allocate(segments, duration, byte_count):
    """Largest-remainder integer apportionment with exact integer arithmetic."""
    floors, remainders = [], []
    for left, right, _status, _client in segments:
        quotient, remainder = divmod(byte_count * (right - left), duration)
        floors.append(quotient)
        remainders.append(remainder)
    extra = byte_count - sum(floors)
    order = sorted(range(len(segments)), key=lambda i: (-remainders[i], segments[i][0]))
    for i in order[:extra]:
        floors[i] += 1
    return floors


def build_report(db, cidr, coverage_start, clock, snapshot_seq, flows):
    """Build the attributing report inside an existing read transaction."""
    net = ipaddress.ip_network(cidr, strict=True)
    usable = pool_bounds(net)
    parsed = parse_flows(flows, clock)
    tick_cache = {}
    totals = {}
    report_flows = []
    for flow in parsed:
        ip = flow['ip']
        ticks = ()
        if usable[0] <= ip <= usable[1]:
            if ip not in tick_cache:
                tick_cache[ip] = _ticks_for_address(db, ip, snapshot_seq)
            ticks = tick_cache[ip]
        segments = _flow_segments(coverage_start, usable, ip, ticks,
                                  flow['start'], flow['end'])
        allocated = _allocate(segments, flow['end'] - flow['start'], flow['bytes'])
        output_segments = []
        for (left, right, status, client), amount in zip(segments, allocated):
            output_segments.append({'start': left, 'end': right, 'status': status,
                                    'client': client, 'bytes': amount})
            key = (status, client)
            totals[key] = totals.get(key, 0) + amount
        report_flows.append({'id': flow['id'], 'address': flow['address'],
                             'start': flow['start'], 'end': flow['end'],
                             'bytes': flow['bytes'], 'segments': output_segments})
    report_flows.sort(key=lambda item: item['id'])
    report_totals = [{'status': status, 'client': client, 'bytes': amount}
                     for (status, client), amount in sorted(
                         totals.items(), key=lambda item: (item[0][0], item[0][1] or ''))]
    return {'cidr': cidr, 'coverage_start': coverage_start, 'clock': clock,
            'snapshot_seq': snapshot_seq, 'flows': report_flows,
            'totals': report_totals}
