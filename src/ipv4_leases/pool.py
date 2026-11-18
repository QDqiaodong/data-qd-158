"""Exclusive live IPv4 leases, with explicit monotonic logical clock."""
import ipaddress,sqlite3
from pathlib import Path
from .common import ident,number
from .reconcile import parse_request,plan

def network(cidr):
    if not isinstance(cidr,str):raise ValueError('CIDR required')
    n=ipaddress.ip_network(cidr,strict=True)
    if n.version!=4 or n.prefixlen<20:raise ValueError('IPv4 /20../32 required')
    return n

class Pool:
    def __init__(self,path):
        self.db=sqlite3.connect(str(path),timeout=10)
        self.db.execute('PRAGMA foreign_keys=ON')
    def close(self):self.db.close()
    def initialize(self,cidr):
        n=network(cidr)
        with self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), cidr TEXT NOT NULL, clock INTEGER NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS leases (client TEXT PRIMARY KEY, address INTEGER NOT NULL UNIQUE, expires INTEGER NOT NULL)')
            row=self.db.execute('SELECT cidr FROM metadata WHERE id=1').fetchone()
            if row and row[0]!=str(n):raise ValueError('pool already initialized with different network')
            self.db.execute('INSERT OR IGNORE INTO metadata VALUES (1,?,0)',(str(n),))
        return {'cidr':str(n),'usable':len(list(n.hosts()))}
    def operate(self,kind,now,client=None,ttl=None):
        now=number(now,0,10**12)
        if kind not in ('acquire','release','list'):raise ValueError('unknown operation')
        if kind!='list':ident(client)
        if kind=='acquire':ttl=number(ttl,1,10**9)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            row=self.db.execute('SELECT cidr,clock FROM metadata WHERE id=1').fetchone()
            if not row:raise ValueError('initialize pool first')
            cidr,clock=row
            if now<clock:raise ValueError('clock cannot move backward')
            self.db.execute('DELETE FROM leases WHERE expires<=?',(now,))
            self.db.execute('UPDATE metadata SET clock=? WHERE id=1',(now,))
            if kind=='acquire':
                old=self.db.execute('SELECT address FROM leases WHERE client=?',(client,)).fetchone()
                used={r[0] for r in self.db.execute('SELECT address FROM leases')}
                address=old[0] if old else next((int(a) for a in network(cidr).hosts() if int(a) not in used),None)
                if address is None:raise ValueError('pool exhausted')
                self.db.execute('INSERT INTO leases VALUES(?,?,?) ON CONFLICT(client) DO UPDATE SET expires=excluded.expires',(client,address,now+ttl))
            elif kind=='release':self.db.execute('DELETE FROM leases WHERE client=?',(client,))
            leases=[{'client':c,'address':str(ipaddress.IPv4Address(a)),'expires':e} for c,a,e in self.db.execute('SELECT client,address,expires FROM leases ORDER BY address')]
            self.db.commit();return {'cidr':cidr,'clock':now,'leases':leases}
        except Exception:
            self.db.rollback();raise
    def reconcile(self,now,demands,blocked):
        """Authoritatively replace the live lease set in one transaction.

        ``demands``/``blocked`` are the raw contract values; validation and
        the two-level optimisation happen here.  Any error rolls back leases,
        expiry cleanup and the clock.
        """
        now,demands,blocked_ranges=parse_request(now,demands,blocked)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            row=self.db.execute('SELECT cidr,clock FROM metadata WHERE id=1').fetchone()
            if not row:raise ValueError('initialize pool first')
            cidr,clock=row
            if now<clock:raise ValueError('clock cannot move backward')
            old_active={c:a for c,a,e in self.db.execute('SELECT client,address,expires FROM leases WHERE expires>?',(now,))}
            net=network(cidr)
            assigned=plan(net,demands,blocked_ranges,old_active)
            self.db.execute('DELETE FROM leases')
            for client,ttl,_ in demands:
                self.db.execute('INSERT INTO leases VALUES(?,?,?)',(client,assigned[client],now+ttl))
            self.db.execute('UPDATE metadata SET clock=? WHERE id=1',(now,))
            leases=[{'client':c,'address':str(ipaddress.IPv4Address(a)),'expires':e} for c,a,e in self.db.execute('SELECT client,address,expires FROM leases ORDER BY address')]
            moved=sorted(client for client in old_active if client in assigned and assigned[client]!=old_active[client])
            self.db.commit();return {'cidr':cidr,'clock':now,'leases':leases,'moved_clients':moved}
        except Exception:
            self.db.rollback();raise
