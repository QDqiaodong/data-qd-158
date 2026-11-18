"""Exclusive live IPv4 leases, with explicit monotonic logical clock."""
import ipaddress,sqlite3
from pathlib import Path
from .common import ident,number
from .reconcile import parse_request,plan

HISTORY_TABLES=(
    'CREATE TABLE IF NOT EXISTS history_meta (id INTEGER PRIMARY KEY CHECK(id=1), coverage_start INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS history_events (seq INTEGER PRIMARY KEY, now INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS history_changes (seq INTEGER NOT NULL, address INTEGER NOT NULL, client TEXT, expires INTEGER, PRIMARY KEY(seq,address))',
    'CREATE INDEX IF NOT EXISTS history_changes_address ON history_changes(address,seq)',
)

def network(cidr):
    if not isinstance(cidr,str):raise ValueError('CIDR required')
    n=ipaddress.ip_network(cidr,strict=True)
    if n.version!=4 or n.prefixlen<20:raise ValueError('IPv4 /20../32 required')
    return n

class Pool:
    def __init__(self,path):
        self.path=str(path)
        self.db=sqlite3.connect(self.path,timeout=10)
        self.db.execute('PRAGMA foreign_keys=ON')
    def close(self):self.db.close()
    def initialize(self,cidr):
        """Create the pool, recording history from clock 0 for a new pool.

        A brand-new database starts history coverage at clock 0 with the empty
        baseline as ``seq=0``.  Initializing an existing database (including a
        legacy one without history) never changes an existing coverage point
        or sequence and never backfills facts.
        """
        n=network(cidr)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), cidr TEXT NOT NULL, clock INTEGER NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS leases (client TEXT PRIMARY KEY, address INTEGER NOT NULL UNIQUE, expires INTEGER NOT NULL)')
            row=self.db.execute('SELECT cidr FROM metadata WHERE id=1').fetchone()
            if row and row[0]!=str(n):raise ValueError('pool already initialized with different network')
            if not row:
                self.db.execute('INSERT INTO metadata VALUES (1,?,0)',(str(n),))
                for statement in HISTORY_TABLES:self.db.execute(statement)
                self.db.execute('INSERT INTO history_meta VALUES (1,0)')
                self.db.execute('INSERT INTO history_events VALUES (0,0)')
            self.db.commit()
        except Exception:
            self.db.rollback();raise
        return {'cidr':str(n),'usable':len(list(n.hosts()))}
    def _coverage(self):
        """Coverage start of the append-only history, or ``None``."""
        try:
            row=self.db.execute('SELECT coverage_start FROM history_meta WHERE id=1').fetchone()
        except sqlite3.OperationalError:
            return None
        return row[0] if row else None
    def enable_history(self):
        """Start recording lease history without backfilling earlier facts.

        Idempotent: the coverage start is the clock at the first successful
        call, and the baseline snapshot is that pool state at ``seq=0``.
        Enabling neither advances the clock nor touches the live leases.
        """
        try:
            self.db.execute('BEGIN IMMEDIATE')
            row=self.db.execute('SELECT cidr,clock FROM metadata WHERE id=1').fetchone()
            if not row:raise ValueError('initialize pool first')
            cidr,clock=row
            for statement in HISTORY_TABLES:self.db.execute(statement)
            existing=self.db.execute('SELECT coverage_start FROM history_meta WHERE id=1').fetchone()
            if existing is None:
                coverage=clock
                self.db.execute('INSERT INTO history_meta VALUES (1,?)',(coverage,))
                self.db.execute('INSERT INTO history_events VALUES (0,?)',(coverage,))
                for client,address,expires in self.db.execute('SELECT client,address,expires FROM leases ORDER BY address'):
                    self.db.execute('INSERT INTO history_changes VALUES (0,?,?,?)',(address,client,expires))
            else:coverage=existing[0]
            self.db.commit()
            return {'cidr':cidr,'coverage_start':coverage,'clock':clock,'snapshot_seq':0}
        except Exception:
            self.db.rollback();raise
    def _leases_by_address(self):
        return {a:(c,e) for c,a,e in self.db.execute('SELECT client,address,expires FROM leases')}
    def _append_history(self,now,before):
        row=self.db.execute('SELECT MAX(seq) FROM history_events').fetchone()
        seq=(row[0] or 0)+1
        self.db.execute('INSERT INTO history_events VALUES (?,?)',(seq,now))
        after=self._leases_by_address()
        for address in sorted(set(before)|set(after)):
            if before.get(address)==after.get(address):continue
            value=after.get(address)
            if value is None:self.db.execute('INSERT INTO history_changes VALUES (?,?,NULL,NULL)',(seq,address))
            else:self.db.execute('INSERT INTO history_changes VALUES (?,?,?,?)',(seq,address,value[0],value[1]))
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
            history=self._coverage() is not None
            before=self._leases_by_address() if history else None
            self.db.execute('DELETE FROM leases WHERE expires<=?',(now,))
            self.db.execute('UPDATE metadata SET clock=? WHERE id=1',(now,))
            if kind=='acquire':
                old=self.db.execute('SELECT address FROM leases WHERE client=?',(client,)).fetchone()
                used={r[0] for r in self.db.execute('SELECT address FROM leases')}
                address=old[0] if old else next((int(a) for a in network(cidr).hosts() if int(a) not in used),None)
                if address is None:raise ValueError('pool exhausted')
                self.db.execute('INSERT INTO leases VALUES(?,?,?) ON CONFLICT(client) DO UPDATE SET expires=excluded.expires',(client,address,now+ttl))
            elif kind=='release':self.db.execute('DELETE FROM leases WHERE client=?',(client,))
            if history:self._append_history(now,before)
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
            history=self._coverage() is not None
            before=self._leases_by_address() if history else None
            old_active={c:a for c,a,e in self.db.execute('SELECT client,address,expires FROM leases WHERE expires>?',(now,))}
            net=network(cidr)
            assigned=plan(net,demands,blocked_ranges,old_active)
            self.db.execute('DELETE FROM leases')
            for client,ttl,_ in demands:
                self.db.execute('INSERT INTO leases VALUES(?,?,?)',(client,assigned[client],now+ttl))
            self.db.execute('UPDATE metadata SET clock=? WHERE id=1',(now,))
            if history:self._append_history(now,before)
            leases=[{'client':c,'address':str(ipaddress.IPv4Address(a)),'expires':e} for c,a,e in self.db.execute('SELECT client,address,expires FROM leases ORDER BY address')]
            moved=sorted(client for client in old_active if client in assigned and assigned[client]!=old_active[client])
            self.db.commit();return {'cidr':cidr,'clock':now,'leases':leases,'moved_clients':moved}
        except Exception:
            self.db.rollback();raise
    def attribute_flows(self,flows):
        """Attribute sampled flows to historical holders in a read snapshot.

        Runs in one read-only, read-consistent transaction: neither the clock,
        the live leases nor the history are touched, and attribution cannot
        bootstrap history for an old pool.
        """
        from .attribution import build_report
        if not isinstance(flows,list):raise ValueError('flows must be an array')
        connection,owned=self._read_connection()
        try:
            connection.execute('BEGIN')
            row=connection.execute('SELECT cidr,clock FROM metadata WHERE id=1').fetchone()
            if not row:raise ValueError('initialize pool first')
            cidr,clock=row
            try:coverage=connection.execute('SELECT coverage_start FROM history_meta WHERE id=1').fetchone()
            except sqlite3.OperationalError:coverage=None
            if coverage is None:raise ValueError('history not enabled; run history-enable first')
            seq=connection.execute('SELECT MAX(seq) FROM history_events').fetchone()[0] or 0
            report=build_report(connection,cidr,coverage[0],clock,seq,flows)
            connection.commit();return report
        except Exception:
            connection.rollback();raise
        finally:
            if owned:connection.close()
    def _read_connection(self):
        """A second read-only connection so attribution cannot mutate the pool."""
        if self.path in (':memory:',''):
            return self.db,False
        if not Path(self.path).is_file():raise ValueError('initialize pool first')
        uri=Path(self.path).resolve().as_uri()+'?mode=ro'
        return sqlite3.connect(uri,uri=True,timeout=10),True
