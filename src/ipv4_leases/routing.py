"""Offline routing-fault impact analysis.

The engine answers one question for every usable host of a pool: which
egress interfaces can still forward traffic to that address, before and
after interface-down scenarios?  Everything is computed offline from a
fixed set of routing facts; no real network is ever touched.

Selection semantics (applied independently to every IPv4 address)
-----------------------------------------------------------------

1. Among all routes whose prefix contains the address, take the longest
   prefix; within that prefix take the smallest ``metric``; every route
   tied on both is kept (equal-cost multipath).  No match means the
   address is unreachable (an empty interface set).
2. A directly connected (``interface``) route contributes its interface.
   A gateway (``via``) route contributes the interface set reached by the
   gateway address, resolved with the *same* selection rules.
3. The result is the least fixed point of those set equations.  A pure
   cycle yields the empty set; a cycle that can reach an exit propagates
   every exit interface -- a cycle never negates a whole branch, and a
   temporarily empty DFS result may never be cached as the final answer.

Fault scenarios start from the original facts each time: only the direct
routes whose ``interface`` is listed in ``down`` are withdrawn.  Gateway
routes are never deleted, an unreachable gateway never causes fallback to
a worse metric, but the shorter prefixes / larger metrics that become
eligible after the withdrawal take part in a fresh selection.

Termination and isolation
-------------------------

The dependency graph is built lazily from the pool hosts and recursively
from gateway addresses, so off-pool IPv4 space is never enumerated and
recursive paths are never expanded.  Interface labels are then computed on
the graph's condensation DAG (iterative Kosaraju, so the 1500-hop chains
need no recursion depth): each strongly connected component receives the
union of its own direct interfaces and the labels of every component
reachable from it, which is exactly the least fixed point above.  Every
scenario builds a fresh engine from a filtered copy of the facts, so no
state leaks between scenarios and no stale exit can survive inside a
cyclic component.
"""
import ipaddress

from .common import ident, number, require
from .reconcile import pool_bounds

MAX_ROUTES = 2048
MAX_SCENARIOS = 32
MAX_DOWN = 2048
METRIC_MAX = 10 ** 9


def strict_ipv4(value):
    """Parse a strict IPv4 text address (no IPv6, no integer, no odd spellings)."""
    if not isinstance(value, str):
        raise ValueError('strict IPv4 address required')
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError('strict IPv4 address required: ' + value) from None
    return int(address)


def strict_cidr(value):
    """Parse a strict IPv4 CIDR in /0../32 without host bits (pool /20 floor does not apply)."""
    if not isinstance(value, str):
        raise ValueError('strict IPv4 CIDR required')
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ValueError('strict IPv4 CIDR required: ' + value) from None
    if net.version != 4:
        raise ValueError('IPv4 CIDR required: ' + value)
    return int(net.network_address), net.prefixlen


def parse_routes(routes):
    """Validate the bounded ``routes`` array; return immutable fact tuples."""
    if not isinstance(routes, list) or len(routes) > MAX_ROUTES:
        raise ValueError('routes must be an array of at most %d items' % MAX_ROUTES)
    parsed, seen_ids, interfaces = [], set(), set()
    for item in routes:
        require(item, 'id prefix metric via interface')
        route_id = ident(item['id'])
        if route_id in seen_ids:
            raise ValueError('duplicate route id: ' + route_id)
        seen_ids.add(route_id)
        network, prefixlen = strict_cidr(item['prefix'])
        metric = number(item['metric'], 0, METRIC_MAX)
        via, interface = item['via'], item['interface']
        if (via is not None) == (interface is not None):
            raise ValueError('exactly one of via/interface must be non-null')
        if via is not None:
            gateway = strict_ipv4(via)
            parsed.append((route_id, network, prefixlen, metric, gateway, None))
        else:
            name = ident(interface)
            interfaces.add(name)
            parsed.append((route_id, network, prefixlen, metric, None, name))
    return parsed, interfaces


def parse_scenarios(scenarios, known_interfaces):
    """Validate the bounded ``scenarios`` array against known interfaces."""
    if not isinstance(scenarios, list) or len(scenarios) > MAX_SCENARIOS:
        raise ValueError('scenarios must be an array of at most %d items' % MAX_SCENARIOS)
    parsed, seen_ids = [], set()
    for item in scenarios:
        require(item, 'id down')
        scenario_id = ident(item['id'])
        if scenario_id in seen_ids:
            raise ValueError('duplicate scenario id: ' + scenario_id)
        seen_ids.add(scenario_id)
        down = item['down']
        if not isinstance(down, list) or len(down) > MAX_DOWN:
            raise ValueError('down must be an array of at most %d interfaces' % MAX_DOWN)
        names, seen_down = [], set()
        for name in down:
            interface = ident(name)
            if interface in seen_down:
                raise ValueError('duplicate down interface: ' + interface)
            if interface not in known_interfaces:
                raise ValueError('unknown down interface: ' + interface)
            seen_down.add(interface)
            names.append(interface)
        parsed.append((scenario_id, frozenset(names)))
    return parsed


class _Trie:
    """Binary trie over 32-bit addresses holding, per prefix node, the
    precomputed set of routes selected at that prefix (the minimum metric
    there).  Longest-prefix match is a 32-step walk with backtracking."""

    __slots__ = ('children', 'routes')

    def __init__(self):
        self.children = [None, None]
        self.routes = None

    def insert(self, network, prefixlen, selected):
        node = self
        for bit_position in range(31, 31 - prefixlen, -1):
            bit = (network >> bit_position) & 1
            nxt = node.children[bit]
            if nxt is None:
                nxt = _Trie()
                node.children[bit] = nxt
            node = nxt
        node.routes = selected

    def select(self, address):
        """Return the equal-best routes for an address, or ``None`` on no match."""
        node = self
        best = None
        if node.routes is not None:
            best = node.routes
        for bit_position in range(31, -1, -1):
            node = node.children[(address >> bit_position) & 1]
            if node is None:
                break
            if node.routes is not None:
                best = node.routes
        return best


class RouteEngine:
    """Selection and recursive interface resolution for one fixed fact set."""

    def __init__(self, routes):
        grouped = {}
        for route in routes:
            _id, network, prefixlen, metric, gateway, interface = route
            grouped.setdefault((network, prefixlen), []).append(route)
        self.trie = _Trie()
        for (network, prefixlen), group in grouped.items():
            minimum = min(route[3] for route in group)
            self.trie.insert(network, prefixlen,
                             [route for route in group if route[3] == minimum])

    def chosen(self, address):
        """The winning route tuple set for an address, or ``None`` if unreachable."""
        return self.trie.select(address)

    def _build_graph(self, roots):
        """Lazily expand the gateway dependency graph reachable from ``roots``."""
        adjacency = {}
        pending = list(roots)
        while pending:
            node = pending.pop()
            if node in adjacency:
                continue
            chosen = self.chosen(node)
            edges = []
            if chosen is not None:
                for route in chosen:
                    if route[4] is not None:
                        edges.append(route[4])
                        if route[4] not in adjacency:
                            pending.append(route[4])
            adjacency[node] = edges
        return adjacency

    @staticmethod
    def _sccs(adjacency, nodes):
        """Iterative Kosaraju; SCCs come out in topological order of the
        condensation DAG (every edge goes from an earlier to a later SCC)."""
        reverse = {node: [] for node in nodes}
        for node in nodes:
            for nxt in adjacency[node]:
                reverse[nxt].append(node)
        visited = set()
        finish_order = []
        for start in nodes:
            if start in visited:
                continue
            visited.add(start)
            stack = [(start, 0)]
            while stack:
                node, index = stack[-1]
                neighbours = adjacency[node]
                if index < len(neighbours):
                    nxt = neighbours[index]
                    stack[-1] = (node, index + 1)
                    if nxt not in visited:
                        visited.add(nxt)
                        stack.append((nxt, 0))
                else:
                    finish_order.append(node)
                    stack.pop()
        component_of = {}
        components = []
        for start in reversed(finish_order):
            if start in component_of:
                continue
            component = []
            component_of[start] = len(components)
            stack = [start]
            while stack:
                node = stack.pop()
                component.append(node)
                for nxt in reverse[node]:
                    if nxt not in component_of:
                        component_of[nxt] = len(components)
                        stack.append(nxt)
            components.append(component)
        return component_of, components

    def labels(self, roots):
        """Least-fixed-point interface sets for every reachable node."""
        adjacency = self._build_graph(roots)
        nodes = list(adjacency)
        component_of, components = self._sccs(adjacency, nodes)
        component_labels = [None] * len(components)
        # SCCs are already topologically ordered, so iterate backwards:
        # successors are always already solved.
        for index in range(len(components) - 1, -1, -1):
            interfaces = set()
            successors = set()
            for node in components[index]:
                chosen = self.chosen(node)
                if chosen is not None:
                    for route in chosen:
                        if route[5] is not None:
                            interfaces.add(route[5])
                for nxt in adjacency[node]:
                    successor = component_of[nxt]
                    if successor != index:  # intra-SCC edges add no new labels
                        successors.add(successor)
            for successor in successors:
                interfaces |= component_labels[successor]
            component_labels[index] = interfaces
        return {node: frozenset(component_labels[component_of[node]]) for node in nodes}

    def resolve(self, addresses):
        """Map each address to its sorted interface list (empty = unreachable)."""
        labels = self.labels(list(addresses))
        return {address: sorted(labels.get(address, ())) for address in addresses}


def _segments(addresses, mapping, key):
    """Group consecutive addresses whose compared sets are equal into the
    maximal closed intervals; intervals are ordered by IPv4 numeric value."""
    result = []
    start = previous = None
    current = None
    for address in addresses:
        value = key(mapping[address])
        if current is None:
            start = previous = address
            current = value
        elif value == current and address == previous + 1:
            previous = address
        else:
            result.append((start, previous, current))
            start = previous = address
            current = value
    if current is not None:
        result.append((start, previous, current))
    return result


def _ip(address):
    return str(ipaddress.IPv4Address(address))


def build_report(cidr, clock, routes_raw, scenarios_raw):
    """Compute the baseline and every fault scenario for one pool's hosts."""
    net = ipaddress.ip_network(cidr, strict=True)
    lo, hi = pool_bounds(net)
    hosts = list(range(lo, hi + 1))
    routes, interfaces = parse_routes(routes_raw)
    scenarios = parse_scenarios(scenarios_raw, interfaces)

    baseline_engine = RouteEngine(routes)
    before = baseline_engine.resolve(hosts)
    baseline = [
        {'start': _ip(start), 'end': _ip(end), 'interfaces': list(values)}
        for start, end, values in _segments(hosts, before, lambda value: tuple(value))
    ]

    outputs = []
    for scenario_id, down in scenarios:
        # Fresh facts per scenario: direct routes on a down interface are
        # withdrawn; gateway routes always remain.  Nothing is shared with
        # the baseline engine or with sibling scenarios.
        surviving = [route for route in routes
                     if route[5] is None or route[5] not in down]
        after = RouteEngine(surviving).resolve(hosts)
        changes, changed_hosts, lost_hosts, recovered_hosts = [], 0, 0, 0
        for start, end, pair in _segments(
                hosts,
                {address: (tuple(before[address]), tuple(after[address])) for address in hosts},
                lambda value: value):
            old, new = pair
            if old == new:
                continue
            changes.append({'start': _ip(start), 'end': _ip(end),
                            'before': list(old), 'after': list(new)})
            count = end - start + 1
            changed_hosts += count
            if old and not new:
                lost_hosts += count
            elif not old and new:
                recovered_hosts += count
        outputs.append({'id': scenario_id, 'changes': changes,
                        'changed_hosts': changed_hosts,
                        'lost_hosts': lost_hosts,
                        'recovered_hosts': recovered_hosts})
    outputs.sort(key=lambda item: item['id'])
    return {'cidr': str(net), 'clock': clock,
            'baseline': baseline, 'scenarios': outputs}
