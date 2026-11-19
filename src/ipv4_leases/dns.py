"""Persistent offline DNS mirror: strict names, config validation, compilation.

Everything in this module is pure Python (standard library only): the pool
layer owns SQLite persistence and the transaction boundaries.  A mirror is
*derived* on demand from the final active leases and the effective config, so
there is never a materialised record row that could go stale; every write
entry point compiles the mirror through :func:`compile_mirror` inside its own
``BEGIN IMMEDIATE`` transaction, and snapshots run the same compiler against a
single read-consistent snapshot.
"""
import ipaddress

from .common import ident

MAX_BINDINGS = 128
MAX_ALIASES = 2048


class DnsError(ValueError):
    """A DNS configuration or integrity violation."""


def normalize_name(value):
    """Validate an ASCII DNS hostname and return its lowercase absolute form.

    The input may carry at most one trailing dot.  The returned name is
    lowercased with exactly one trailing dot.  Unicode/IDNA, underscores,
    empty labels, illegal hyphens, surrounding whitespace, repeated trailing
    dots and label/name length violations are all rejected.
    """
    if not isinstance(value, str):
        raise DnsError('DNS name must be a string')
    if value != value.strip():
        raise DnsError('DNS name must not have surrounding whitespace')
    try:
        value.encode('ascii')
    except UnicodeEncodeError:
        raise DnsError('DNS name must be ASCII; Unicode/IDNA is rejected') from None
    if not value:
        raise DnsError('DNS name must not be empty')
    body = value[:-1] if value.endswith('.') else value
    if not body or body.endswith('.'):
        raise DnsError('empty label or repeated trailing dot in DNS name')
    if not 1 <= len(body.encode('ascii')) <= 253:
        raise DnsError('DNS name length out of bounds (1..253 bytes)')
    labels = body.split('.')
    for label in labels:
        if not 1 <= len(label) <= 63:
            raise DnsError('DNS label length out of bounds (1..63 bytes)')
        if not all(('0' <= c <= '9') or ('a' <= c <= 'z')
                   or ('A' <= c <= 'Z') or c == '-' for c in label):
            raise DnsError('illegal character in DNS label: ' + label)
        if label[0] == '-' or label[-1] == '-':
            raise DnsError('DNS label must not start or end with a hyphen: ' + label)
    return body.lower() + '.'


def in_zone(name, zone):
    """True when ``name`` is the zone apex or ends on a full label boundary."""
    return name == zone or name.endswith('.' + zone)


def validate_config(zone, bindings, aliases):
    """Validate and normalise the four top-level configuration values.

    Returns ``(zone, bindings, aliases)`` where bindings are
    ``(client, name, reverse)`` tuples and aliases are ``(owner, target)``
    tuples using normalized absolute lowercase names.  Client identifiers
    keep their exact ``ident`` semantics (no DNS case folding).
    """
    normalized_zone = normalize_name(zone)
    if not isinstance(bindings, list) or len(bindings) > MAX_BINDINGS:
        raise DnsError('bindings must be an array of at most 128 entries')
    normalized_bindings = []
    seen_clients = set()
    for item in bindings:
        if not isinstance(item, dict) or set(item) != {'client', 'name', 'reverse'}:
            raise DnsError('each binding must be exactly {client,name,reverse}')
        client = ident(item['client'])
        if client in seen_clients:
            raise DnsError('duplicate binding client: ' + client)
        seen_clients.add(client)
        name = normalize_name(item['name'])
        if not in_zone(name, normalized_zone):
            raise DnsError('binding name outside zone %s: %s' % (normalized_zone, name))
        if type(item['reverse']) is not bool:
            raise DnsError('binding reverse must be a real boolean')
        normalized_bindings.append((client, name, item['reverse']))
    if not isinstance(aliases, list) or len(aliases) > MAX_ALIASES:
        raise DnsError('aliases must be an array of at most 2048 entries')
    normalized_aliases = []
    seen_owners = set()
    for item in aliases:
        if not isinstance(item, dict) or set(item) != {'name', 'target'}:
            raise DnsError('each alias must be exactly {name,target}')
        owner = normalize_name(item['name'])
        target = normalize_name(item['target'])
        if owner == normalized_zone:
            raise DnsError('alias owner must not be the zone apex')
        if not in_zone(owner, normalized_zone) or not in_zone(target, normalized_zone):
            raise DnsError('alias name or target outside zone %s' % normalized_zone)
        if owner in seen_owners:
            raise DnsError('duplicate alias owner after normalization: ' + owner)
        seen_owners.add(owner)
        normalized_aliases.append((owner, target))
    return normalized_zone, normalized_bindings, normalized_aliases


def ptr_name(address):
    """Canonical reverse-DNS owner (``d.c.b.a.in-addr.arpa.``) for an address."""
    octets = int(address).to_bytes(4, 'big')
    return '%d.%d.%d.%d.in-addr.arpa.' % (octets[3], octets[2], octets[1], octets[0])


def compile_mirror(zone, bindings, aliases, active, now):
    """Compile the structured DNS mirror for one logical instant.

    ``active`` maps each client with a live lease (``expires > now``) to
    ``(address_int, expires)``.  Only clients named by a binding contribute
    records; external DHCP facts never do.  Raises :class:`DnsError` on an
    A/CNAME owner collision, a cyclic or dangling CNAME chain.  Chain walks
    are iterative with an explicit visited set, so the 1500-level chain limit
    never depends on Python recursion depth.
    """
    name_of = {client: name for client, name, _ in bindings}
    reverse_of = {client: reverse for client, _, reverse in bindings}

    # A RRsets: one entry per bound name, values from every active client
    # bound to that name, TTL the smallest contributing lease remainder.
    a_sets = {}
    for client, (address, expires) in active.items():
        if client not in name_of:
            continue  # unbound clients and external facts contribute nothing
        ttl = expires - now
        if ttl <= 0:
            raise DnsError('internal error: inactive lease offered to mirror')
        name = name_of[client]
        entry = a_sets.get(name)
        if entry is None:
            a_sets[name] = {'ttl': ttl, 'sources': [(address, expires)]}
        else:
            entry['ttl'] = min(entry['ttl'], ttl)
            entry['sources'].append((address, expires))

    alias_map = dict(aliases)
    for owner in alias_map:
        if owner in a_sets:
            raise DnsError('CNAME owner also has active A records: ' + owner)

    # Resolve every chain to its terminal non-empty A RRset.  Memoised
    # terminals make fork/join graphs linear overall; the local visited set
    # gives deterministic cycle detection without recursion.
    terminals = {}

    def resolve(owner):
        path = []
        visited = set()
        current = owner
        while True:
            if current in terminals:
                end = terminals[current]
                for node in path:
                    terminals[node] = end
                return end
            if current in a_sets:
                for node in path:
                    terminals[node] = current
                return current
            if current in visited:
                raise DnsError('CNAME chain contains a cycle at ' + current)
            if current not in alias_map:
                raise DnsError('dangling CNAME chain at ' + current)
            visited.add(current)
            path.append(current)
            current = alias_map[current]

    records = []
    for name in sorted(a_sets):
        entry = a_sets[name]
        values = [str(ipaddress.IPv4Address(address))
                  for address, _ in sorted(entry['sources'])]
        records.append({'name': name, 'type': 'A', 'ttl': entry['ttl'],
                        'values': values})
    for owner, target in aliases:
        terminal = resolve(owner)
        records.append({'name': owner, 'type': 'CNAME',
                        'ttl': a_sets[terminal]['ttl'], 'values': [target]})
    for client, (address, expires) in active.items():
        if client not in name_of or not reverse_of[client]:
            continue
        records.append({'name': ptr_name(address), 'type': 'PTR',
                        'ttl': expires - now, 'values': [name_of[client]]})
    records.sort(key=lambda record: (record['name'], record['type']))
    return records
