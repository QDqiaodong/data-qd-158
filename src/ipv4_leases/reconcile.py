"""One-shot reconciliation of a whole IPv4 lease pool.

The request is an authoritative demand set.  Allocation is a perfect
bipartite matching between demanded clients and candidate addresses with a
two-level objective:

1. minimise the number of clients that had a live lease at the start of the
   transaction and are still demanded but receive a different address;
2. among those allocations, minimise the address vector (clients ordered by
   Python string order, addresses by IPv4 numeric value) lexicographically.

Both levels are encoded into a single integer edge cost and solved with a
min-cost perfect matching (successive shortest augmenting paths).  Candidates
are pruned to the ``n`` smallest allowed usable addresses per client plus that
client's old address; that set provably contains an optimum for both levels,
keeps the graph at ``n + 1`` candidates per client (``n <= 128``), and avoids
enumerating complete allocations.
"""
import ipaddress
from heapq import heappush, heappop

from .common import ident, number, require

MAX_CLIENTS = 128
MAX_CIDRS = 32
MAX_BLOCKED = 128


def cidr_range(value):
    """Strict IPv4 CIDR /0../32 mapped to its inclusive integer range."""
    if not isinstance(value, str):
        raise ValueError('CIDR required')
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ValueError('strict IPv4 CIDR required: ' + value) from None
    if net.version != 4:
        raise ValueError('IPv4 CIDR required: ' + value)
    return int(net.network_address), int(net.broadcast_address)


def parse_request(now, demands, blocked):
    """Validate and normalise the demand request.

    Returns ``(now, demands, blocked_ranges)`` where each demand is
    ``(client, ttl, ranges)``.  Raises ``ValueError`` on any contract
    violation; callers must not have started a transaction yet.
    """
    now = number(now, 0, 10 ** 12)
    if not isinstance(demands, list) or len(demands) > MAX_CLIENTS:
        raise ValueError('demands must be an array of at most 128 clients')
    if not isinstance(blocked, list) or len(blocked) > MAX_BLOCKED:
        raise ValueError('blocked must be an array of at most 128 CIDRs')
    blocked_ranges = [cidr_range(value) for value in blocked]
    parsed, seen = [], set()
    for item in demands:
        require(item, 'client ttl allowed')
        client = ident(item['client'])
        if client in seen:
            raise ValueError('duplicate client: ' + client)
        seen.add(client)
        ttl = number(item['ttl'], 1, 10 ** 9)
        allowed = item['allowed']
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= MAX_CIDRS:
            raise ValueError('allowed must be an array of 1..32 CIDRs')
        parsed.append((client, ttl, [cidr_range(value) for value in allowed]))
    return now, parsed, blocked_ranges


def _merge(ranges, lo, hi):
    clipped = sorted((max(a, lo), min(b, hi)) for a, b in ranges if b >= lo and a <= hi)
    merged = []
    for a, b in clipped:
        if merged and a <= merged[-1][1] + 1:
            if b > merged[-1][1]:
                merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a, b))
    return merged


def pool_bounds(net):
    """Usable host range for a pool network (contiguous under ipaddress)."""
    first, last = int(net.network_address), int(net.broadcast_address)
    if first < last and net.prefixlen <= 30:
        return first + 1, last - 1
    return first, last


def _candidates(merged, blocked, lo, count):
    """Ascending usable ranks (offset from ``lo``), stopping after ``count``."""
    result = []
    for a, b in merged:
        for address in range(a, b + 1):
            rank = address - lo
            if not blocked[rank]:
                result.append(rank)
                if len(result) >= count:
                    return result
    return result


def _allowed(rank, lo, merged, blocked):
    if blocked[rank]:
        return False
    address = lo + rank
    return any(a <= address <= b for a, b in merged)


def _minimum_cost_matching(client_count, candidate_ranks, costs):
    """Min-cost perfect matching.  Returns assigned rank per client."""
    if client_count == 0:
        return []
    address_nodes = {}
    rank_of_node = {}
    for ranks in candidate_ranks:
        for rank in ranks:
            if rank not in address_nodes:
                node = len(address_nodes)
                address_nodes[rank] = node
                rank_of_node[node] = rank
    source = 0
    client_base = 1
    address_base = client_base + client_count
    sink = address_base + len(address_nodes)
    graph = [[] for _ in range(sink + 1)]

    def add_edge(u, v, capacity, cost):
        graph[u].append([v, capacity, cost, len(graph[v])])
        graph[v].append([u, 0, -cost, len(graph[u]) - 1])

    for i in range(client_count):
        add_edge(source, client_base + i, 1, 0)
    for rank, node in address_nodes.items():
        add_edge(address_base + node, sink, 1, 0)
    forward = []
    for i in range(client_count):
        edges = []
        for rank, cost in zip(candidate_ranks[i], costs[i]):
            node = address_nodes[rank]
            add_edge(client_base + i, address_base + node, 1, cost)
            edges.append((address_base + node, len(graph[client_base + i]) - 1))
        forward.append(edges)

    node_count = sink + 1
    potential = [0] * node_count
    flow = 0
    while flow < client_count:
        dist = [None] * node_count
        prev_node = [-1] * node_count
        prev_edge = [-1] * node_count
        dist[source] = 0
        heap = [(0, source)]
        while heap:
            d, u = heappop(heap)
            if d != dist[u]:
                continue
            base = potential[u]
            for index, edge in enumerate(graph[u]):
                if edge[1] <= 0:
                    continue
                v = edge[0]
                nd = d + edge[2] + base - potential[v]
                if dist[v] is None or nd < dist[v]:
                    dist[v] = nd
                    prev_node[v] = u
                    prev_edge[v] = index
                    heappush(heap, (nd, v))
        if dist[sink] is None:
            raise ValueError('no complete allocation')
        for v in range(node_count):
            if dist[v] is not None:
                potential[v] += dist[v]
        v = sink
        while v != source:
            u, index = prev_node[v], prev_edge[v]
            edge = graph[u][index]
            edge[1] -= 1
            graph[v][edge[3]][1] += 1
            v = u
        flow += 1

    assigned = [None] * client_count
    for i, edges in enumerate(forward):
        for node, index in edges:
            if graph[client_base + i][index][1] == 0:
                assigned[i] = rank_of_node[node - address_base]
                break
        if assigned[i] is None:  # pragma: no cover - flow conservation guard
            raise ValueError('no complete allocation')
    return assigned


def plan(net, demands, blocked_ranges, old_active):
    """Compute the authoritative allocation.

    ``demands`` is the parsed list of ``(client, ttl, ranges)``; ``old_active``
    maps clients that held a live lease at transaction start to their address.
    Returns ``{client: address}`` or raises ``ValueError`` if infeasible.
    """
    lo, hi = pool_bounds(net)
    size = hi - lo + 1
    blocked = bytearray(size)
    for a, b in _merge(blocked_ranges, lo, hi):
        blocked[a - lo:b - lo + 1] = b'\x01' * (b - a + 1)

    count = len(demands)
    if count == 0:
        return {}
    if size < count:
        raise ValueError('no complete allocation')

    clients = [client for client, _, _ in demands]
    position = {client: index for index, client in enumerate(sorted(clients))}
    base = size + 1
    powers = [1] * count
    for index in range(1, count):
        powers[index] = powers[index - 1] * base
    primary = powers[-1] * base  # strictly greater than any secondary sum

    candidate_ranks, costs = [], []
    for client, _, allowed_ranges in demands:
        merged = _merge(allowed_ranges, lo, hi)
        # Keeping the client's n smallest allowed addresses plus its old
        # address is sufficient for both objective levels: any assignment
        # using a larger address can hand that client a smaller free allowed
        # address without worsening the move count (the only reason to keep a
        # larger address is that it is the old one, kept explicitly).
        ranks = _candidates(merged, blocked, lo, count)
        old = old_active.get(client)
        old_rank = old - lo if old is not None and lo <= old <= hi else None
        if old_rank is not None and old_rank not in ranks and _allowed(old_rank, lo, merged, blocked):
            ranks = sorted(ranks + [old_rank])
        weight = powers[count - 1 - position[client]]
        eligible_old = old_rank if old_rank is not None and _allowed(old_rank, lo, merged, blocked) else None
        row = []
        for rank in ranks:
            moved = 0 if rank == eligible_old else 1
            row.append(moved * primary + rank * weight)
        candidate_ranks.append(ranks)
        costs.append(row)

    assigned_ranks = _minimum_cost_matching(count, candidate_ranks, costs)
    return {client: lo + rank for (client, _, _), rank in zip(demands, assigned_ranks)}
