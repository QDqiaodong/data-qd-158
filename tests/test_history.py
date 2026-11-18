import hashlib,ipaddress,json,random,sqlite3,subprocess,sys,tempfile,unittest,concurrent.futures
from pathlib import Path
from ipv4_leases.pool import Pool
from ipv4_leases.attribution import MAX_BYTES

ROOT=Path(__file__).resolve().parents[1]

def flow(fid,address,start,end,byte_count):
 return {'id':fid,'address':address,'start':start,'end':end,'bytes':byte_count}

def demand(client,ttl,*allowed):return {'client':client,'ttl':ttl,'allowed':list(allowed)}

def strip_history(pool):
 """Turn a freshly initialized pool into a pre-history legacy database."""
 for name in ('history_changes','history_events','history_meta'):
  pool.db.execute(f'DROP TABLE IF EXISTS {name}')
 pool.db.commit()

class HistoryBase(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'pool.sqlite';self.pool=Pool(self.path)
  self.pool.initialize('192.0.2.0/29')
 def tearDown(self):self.pool.close();self.tmp.cleanup()
 def reopen(self):
  self.pool.close();self.pool=Pool(self.path);return self.pool
 def attribute(self,flows):
  self.pool.operate('list',max(f['end'] for f in flows) if flows else 0)
  return self.pool.attribute_flows(flows)

class Enabling(HistoryBase):
 def test_enable_on_new_pool(self):
  out=self.pool.enable_history()
  self.assertEqual(out,{'cidr':'192.0.2.0/29','coverage_start':0,'clock':0,'snapshot_seq':0})
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],0)
  self.assertEqual(self.pool.operate('list',0)['leases'],[])

 def test_legacy_pool_requires_explicit_enable_and_does_not_backfill(self):
  # Build a database the old way: no history tables exist yet.
  strip_history(self.pool)
  self.pool.operate('acquire',0,'A',3);self.pool.operate('list',5)
  self.assertEqual(self.pool.db.execute("SELECT name FROM sqlite_master WHERE name='history_meta'").fetchone(),None)
  with self.assertRaisesRegex(ValueError,'history not enabled'):self.pool.attribute_flows([])
  # A failed query must not quietly migrate the schema.
  self.assertEqual(self.pool.db.execute("SELECT name FROM sqlite_master WHERE name='history_meta'").fetchone(),None)
  self.assertTrue(self.pool.db.execute('SELECT client,address,expires FROM leases').fetchall()==[])
  self.assertEqual(self.pool.enable_history(),{'cidr':'192.0.2.0/29','coverage_start':5,'clock':5,'snapshot_seq':0})
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],5)
  # The only baseline row is the current (empty) lease set at seq 0.
  self.assertEqual(self.pool.db.execute('SELECT seq,now FROM history_events').fetchall(),[(0,5)])
  self.assertEqual(self.pool.db.execute('SELECT * FROM history_changes').fetchall(),[])

 def test_legacy_enable_snapshots_current_leases(self):
  strip_history(self.pool)
  self.pool.operate('acquire',0,'A',10);self.pool.operate('list',4)
  self.pool.close();self.pool=Pool(self.path)
  self.assertEqual(self.pool.enable_history()['coverage_start'],4)
  self.assertEqual(self.pool.db.execute('SELECT seq,address,client,expires FROM history_changes').fetchall(),
   [(0,3221225985,'A',10)])
  report=self.attribute([flow('a','192.0.2.1',3,6,9)])
  self.assertEqual(report['flows'][0]['segments'],
   [{'start':3,'end':4,'status':'unknown','client':None,'bytes':3},
    {'start':4,'end':6,'status':'owned','client':'A','bytes':6}])

 def test_repeated_enable_is_idempotent_and_advances_nothing(self):
  strip_history(self.pool)
  self.pool.operate('acquire',0,'A',10);self.pool.operate('list',3)
  first=self.pool.enable_history();self.pool.operate('acquire',4,'B',10)
  second=self.pool.enable_history();other=Pool(self.path)
  try:third=other.enable_history()
  finally:other.close()
  self.assertEqual(first,{'cidr':'192.0.2.0/29','coverage_start':3,'clock':3,'snapshot_seq':0})
  self.assertEqual(second,{'cidr':'192.0.2.0/29','coverage_start':3,'clock':4,'snapshot_seq':0})
  self.assertEqual(third,second)
  self.assertEqual(self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall(),[(0,3),(1,4)])
  self.assertEqual(sorted(self.pool.db.execute('SELECT client,address,expires FROM leases').fetchall()),
   [('A',3221225985,10),('B',3221225986,14)])

 def test_enable_does_not_touch_leases_or_expire(self):
  self.pool.operate('acquire',0,'OLD',1);self.pool.operate('acquire',0,'A',10)
  out=self.pool.enable_history()
  self.assertEqual(out['clock'],0)
  self.assertEqual(sorted(c for c,_,_ in self.pool.db.execute('SELECT client,address,expires FROM leases')),['A','OLD'])

 def test_duplicate_list_writes_a_history_row(self):
  self.pool.enable_history();self.pool.operate('list',0);self.pool.operate('list',0)
  self.assertEqual(self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall(),[(0,0),(1,0),(2,0)])
  self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM history_changes WHERE seq>0').fetchone()[0],0)

 def test_failed_operations_leave_no_history_and_consume_no_seq(self):
  self.pool.enable_history();self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10);self.pool.operate('acquire',0,'C',10)
  before=self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall()
  for call in [lambda:self.pool.operate('list',-1),
               lambda:self.pool.reconcile(2,[demand('X',1,'192.0.2.1/32'),demand('Y',1,'192.0.2.1/32')],[]),
               lambda:self.pool.operate('acquire',1,'D',0)]:
   with self.assertRaises(ValueError):call()
  self.assertEqual(self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall(),before)
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],0)
  self.assertEqual(self.pool.attribute_flows([])['snapshot_seq'],3)

 def test_failed_reconcile_rolls_back_history_and_seq(self):
  self.pool.enable_history();self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  before=(self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall(),
          self.pool.db.execute('SELECT client,address,expires FROM leases ORDER BY address').fetchall(),
          self.pool.db.execute('SELECT clock FROM metadata').fetchone())
  with self.assertRaisesRegex(ValueError,'no complete allocation'):
   self.pool.reconcile(5,[demand('A',5,'192.0.2.1/32'),demand('B',5,'192.0.2.1/32')],[])
  self.assertEqual(before,(self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall(),
                           self.pool.db.execute('SELECT client,address,expires FROM leases ORDER BY address').fetchall(),
                           self.pool.db.execute('SELECT clock FROM metadata').fetchone()))
  self.assertEqual(self.pool.attribute_flows([])['snapshot_seq'],2)

 def test_history_write_failure_rolls_back_leases_clock_and_seq(self):
  self.pool.enable_history();self.pool.operate('acquire',0,'A',10)
  self.pool.db.execute("CREATE TRIGGER boom BEFORE INSERT ON history_events WHEN NEW.seq>1 BEGIN SELECT RAISE(ABORT,'injected'); END")
  with self.assertRaises(sqlite3.DatabaseError):self.pool.operate('acquire',1,'B',10)
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],0)
  self.assertEqual([(r[0],r[1]) for r in self.pool.db.execute('SELECT client,address FROM leases')],[('A',3221225985)])
  self.assertEqual(self.pool.db.execute('SELECT MAX(seq) FROM history_events').fetchone()[0],1)
  self.pool.db.execute('DROP TRIGGER boom')
  self.assertEqual(self.pool.operate('acquire',1,'B',10)['clock'],1)
  self.assertEqual(self.pool.db.execute('SELECT MAX(seq) FROM history_events').fetchone()[0],2)

 def test_concurrent_enable_is_idempotent(self):
  def enable(index):
   p=Pool(self.path)
   try:return p.enable_history()
   finally:p.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:results=list(executor.map(enable,range(4)))
  self.assertEqual({(r['coverage_start'],r['snapshot_seq']) for r in results},{(0,0)})
  self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM history_meta').fetchone()[0],1)
  self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM history_events').fetchone()[0],1)

 def test_concurrent_writes_and_reads_see_one_snapshot(self):
  self.pool.enable_history()
  def write(index):
   p=Pool(self.path)
   try:
    if index%2:return p.reconcile(0,[demand('R',10,'192.0.2.0/29')],[])
    return p.operate('acquire',0,f'C{index}',10)
   finally:p.close()
  def read(_):
   p=Pool(self.path)
   try:return p.attribute_flows([])['snapshot_seq']
   finally:p.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
   futures=[executor.submit(write,i) for i in range(4)]+[executor.submit(read,i) for i in range(8)]
   for future in futures:future.result()
  events=self.pool.db.execute('SELECT seq FROM history_events ORDER BY seq').fetchall()
  self.assertEqual([e[0] for e in events],list(range(len(events))))
  report=self.pool.attribute_flows([])
  self.assertEqual(report['snapshot_seq'],len(events)-1)

class Attribution(HistoryBase):
 def setUp(self):
  super().setUp();self.pool.enable_history()

 def test_acceptance_shortened_renewal(self):
  # A owns .1 [0,10), renews at 4 for 2 ticks, B gets .1 at 8.
  self.pool.operate('acquire',0,'A',10)
  self.pool.operate('acquire',4,'A',2)
  self.pool.operate('acquire',8,'B',18)
  self.pool.operate('list',12)
  report=self.attribute([flow('f','192.0.2.1',0,12,7)])
  self.assertEqual(report['flows'][0]['segments'],[
   {'start':0,'end':6,'status':'owned','client':'A','bytes':4},
   {'start':6,'end':8,'status':'free','client':None,'bytes':1},
   {'start':8,'end':12,'status':'owned','client':'B','bytes':2}])
  self.assertEqual(report['totals'],[
   {'status':'free','client':None,'bytes':1},
   {'status':'owned','client':'A','bytes':4},
   {'status':'owned','client':'B','bytes':2}])

 def test_same_tick_last_operation_wins(self):
  self.pool.operate('acquire',0,'A',10)
  self.pool.operate('acquire',5,'A',10)
  self.pool.operate('release',5,'A')
  self.pool.operate('acquire',5,'B',10)
  report=self.attribute([flow('f','192.0.2.1',0,10,10)])
  self.assertEqual(report['flows'][0]['segments'],[
   {'start':0,'end':5,'status':'owned','client':'A','bytes':5},
   {'start':5,'end':10,'status':'owned','client':'B','bytes':5}])

 def test_same_tick_release_only_leaves_free(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('release',3,'A')
  self.assertEqual(self.attribute([flow('f','192.0.2.1',0,10,4)])['flows'][0]['segments'],
   [{'start':0,'end':3,'status':'owned','client':'A','bytes':1},
    {'start':3,'end':10,'status':'free','client':None,'bytes':3}])

 def test_exact_expiry_is_free(self):
  self.pool.operate('acquire',0,'A',5)
  self.assertEqual(self.attribute([flow('f','192.0.2.1',2,8,6)])['flows'][0]['segments'],
   [{'start':2,'end':5,'status':'owned','client':'A','bytes':3},
    {'start':5,'end':8,'status':'free','client':None,'bytes':3}])

 def test_renewal_may_extend(self):
  self.pool.operate('acquire',0,'A',5);self.pool.operate('acquire',3,'A',20)
  self.assertEqual(self.attribute([flow('f','192.0.2.1',0,23,23)])['flows'][0]['segments'],
   [{'start':0,'end':23,'status':'owned','client':'A','bytes':23}])

 def test_list_expiry_creates_a_state_change(self):
  self.pool.operate('acquire',0,'A',5);self.pool.operate('list',7)
  self.assertEqual(self.attribute([flow('f','192.0.2.1',0,8,8)])['flows'][0]['segments'],
   [{'start':0,'end':5,'status':'owned','client':'A','bytes':5},
    {'start':5,'end':8,'status':'free','client':None,'bytes':3}])

 def test_reconcile_swap(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  self.pool.reconcile(4,[demand('A',4,'192.0.2.2/32'),demand('B',4,'192.0.2.1/32')],[])
  report=self.attribute([flow('a','192.0.2.1',0,8,8),flow('b','192.0.2.2',0,8,8)])
  self.assertEqual(report['flows'][0]['segments'],[
   {'start':0,'end':4,'status':'owned','client':'A','bytes':4},
   {'start':4,'end':8,'status':'owned','client':'B','bytes':4}])
  self.assertEqual(report['flows'][1]['segments'],[
   {'start':0,'end':4,'status':'owned','client':'B','bytes':4},
   {'start':4,'end':8,'status':'owned','client':'A','bytes':4}])

 def test_reconcile_deletes_and_swaps(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10);self.pool.operate('acquire',0,'C',10)
  self.pool.reconcile(2,[demand('B',4,'192.0.2.1/32'),demand('A',4,'192.0.2.2/32')],[])
  report=self.attribute([flow('c','192.0.2.3',0,6,6),flow('a','192.0.2.1',0,6,6)])
  by_id={item['id']:item['segments'] for item in report['flows']}
  self.assertEqual(by_id['a'],
   [{'start':0,'end':2,'status':'owned','client':'A','bytes':2},
    {'start':2,'end':6,'status':'owned','client':'B','bytes':4}])
  self.assertEqual(by_id['c'],
   [{'start':0,'end':2,'status':'owned','client':'C','bytes':2},
    {'start':2,'end':6,'status':'free','client':None,'bytes':4}])

 def test_unknown_before_coverage_start(self):
  self.pool.close();self.tmp.cleanup()
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'legacy.sqlite';self.pool=Pool(self.path)
  self.pool.initialize('192.0.2.0/29');strip_history(self.pool)
  self.pool.operate('acquire',0,'A',20);self.pool.operate('list',5)
  self.pool.enable_history();self.pool.operate('release',7,'A')
  report=self.attribute([flow('f','192.0.2.1',0,10,10),flow('g','192.0.2.4',0,10,10)])
  self.assertEqual(report['flows'][0]['segments'],[
   {'start':0,'end':5,'status':'unknown','client':None,'bytes':5},
   {'start':5,'end':7,'status':'owned','client':'A','bytes':2},
   {'start':7,'end':10,'status':'free','client':None,'bytes':3}])
  self.assertEqual(report['flows'][1]['segments'],[
   {'start':0,'end':5,'status':'unknown','client':None,'bytes':5},
   {'start':5,'end':10,'status':'free','client':None,'bytes':5}])

 def test_outside_pool_beats_unknown(self):
  report=self.attribute([flow('n','192.0.2.0',0,9,9),flow('b','192.0.2.7',0,9,9),
                                    flow('x','198.51.100.1',0,9,9)])
  for item in report['flows']:
   self.assertEqual(item['segments'],[{'start':0,'end':9,'status':'outside_pool','client':None,'bytes':9}])

 def test_slash31_and_slash32_pools(self):
  for index,cidr,address in [(1,'192.0.2.0/31','192.0.2.0'),(2,'192.0.2.9/32','192.0.2.9')]:
   p=Pool(Path(self.tmp.name)/f'small{index}.sqlite')
   try:
    p.initialize(cidr);p.enable_history();p.operate('acquire',2,'A',5);p.operate('list',7)
    inside=p.attribute_flows([flow('f',address,0,7,7)])['flows'][0]['segments']
    self.assertEqual(inside,[{'start':0,'end':2,'status':'free','client':None,'bytes':2},
                             {'start':2,'end':7,'status':'owned','client':'A','bytes':5}])
    outside='192.0.2.2' if cidr.endswith('/31') else '192.0.2.8'
    self.assertEqual(p.attribute_flows([flow('o',outside,0,7,7)])['flows'][0]['segments'],
     [{'start':0,'end':7,'status':'outside_pool','client':None,'bytes':7}])
   finally:p.close()

 def test_zero_bytes_and_remainder_ties(self):
  self.pool.operate('acquire',0,'A',2);self.pool.operate('release',2,'A')
  self.assertEqual(self.attribute([flow('z','192.0.2.1',0,4,0)])['flows'][0]['segments'],
   [{'start':0,'end':2,'status':'owned','client':'A','bytes':0},
    {'start':2,'end':4,'status':'free','client':None,'bytes':0}])
  # Equal remainders (1/2 each): the extra byte goes to the earlier start.
  self.assertEqual(self.attribute([flow('t','192.0.2.1',0,4,1)])['flows'][0]['segments'],
   [{'start':0,'end':2,'status':'owned','client':'A','bytes':1},
    {'start':2,'end':4,'status':'free','client':None,'bytes':0}])
  # Three equal spans with 2 bytes: largest remainder ties broken by start.
  self.pool.operate('acquire',4,'B',2)
  segments=self.attribute([flow('u','192.0.2.1',0,6,2)])['flows'][0]['segments']
  self.assertEqual(sum(s['bytes'] for s in segments),2)
  self.assertEqual([s['status'] for s in segments],['owned','free','owned'])
  self.assertEqual([s['bytes'] for s in segments],[1,1,0])

 def test_large_bytes_conserve_exactly(self):
  self.pool.operate('acquire',0,'A',3);self.pool.operate('release',3,'A');self.pool.operate('acquire',7,'B',5)
  amount=MAX_BYTES
  report=self.attribute([flow('big','192.0.2.1',0,12,amount)])
  segments=report['flows'][0]['segments']
  self.assertEqual(sum(s['bytes'] for s in segments),amount)
  self.assertEqual([(s['start'],s['end'],s['status'],s['client'],s['bytes']) for s in segments],[
   (0,3,'owned','A',250000000000000000),(3,7,'free',None,333333333333333333),
   (7,12,'owned','B',416666666666666667)])
  self.assertEqual(sum(t['bytes'] for t in report['totals']),amount)

 def test_adjacent_same_holder_merges(self):
  self.pool.operate('acquire',0,'A',5);self.pool.operate('acquire',5,'A',5);self.pool.operate('list',5)
  self.assertEqual(self.attribute([flow('m','192.0.2.1',0,10,10)])['flows'][0]['segments'],
   [{'start':0,'end':10,'status':'owned','client':'A','bytes':10}])

 def test_flow_validation(self):
  self.pool.operate('list',10)
  good=flow('a','192.0.2.1',0,10,10)
  bad=[
   {'flows':[good,good]},
   {'flows':[dict(good,x=1)]},
   {'flows':[dict(good,address='192.0.2.01')]},
   {'flows':[dict(good,address='2001:db8::1')]},
   {'flows':[dict(good,address='192.0.2.1/32')]},
   {'flows':[dict(good,start=5,end=5)]},
   {'flows':[dict(good,start=6,end=5)]},
   {'flows':[dict(good,end=11)]},
   {'flows':[dict(good,start=-1)]},
   {'flows':[dict(good,bytes=-1)]},
   {'flows':[dict(good,bytes=MAX_BYTES+1)]},
   {'flows':[dict(good,start=True)]},
   {'flows':[dict(good,bytes=1.0)]},
   {'flows':[dict(good,id='')]},
   {'flows':[good]*10001},
   {'flows':good},
  ]
  for request in bad:
   with self.subTest(request=str(request)[:60]),self.assertRaises(ValueError):self.pool.attribute_flows(request['flows'] if 'flows' in request else request)
  self.assertEqual(self.pool.attribute_flows([good])['flows'][0]['segments'],
   [{'start':0,'end':10,'status':'free','client':None,'bytes':10}])

 def test_query_is_read_only_and_old_list_untouched(self):
  self.pool.operate('acquire',0,'A',10)
  before=(self.pool.db.execute('SELECT clock FROM metadata').fetchone(),
          self.pool.db.execute('SELECT client,address,expires FROM leases ORDER BY address').fetchall(),
          self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall())
  report=self.attribute([flow('f','192.0.2.1',0,5,5)])
  self.assertEqual(report['clock'],5);self.assertEqual(report['snapshot_seq'],2)
  after=(self.pool.db.execute('SELECT clock FROM metadata').fetchone(),
         self.pool.db.execute('SELECT client,address,expires FROM leases ORDER BY address').fetchall(),
         self.pool.db.execute('SELECT seq,now FROM history_events ORDER BY seq').fetchall())
  self.assertEqual(before[0],(0,))
  # Only the test helper's own list commit is visible; attribution added nothing.
  self.assertEqual(after[0],(5,));self.assertEqual(after[2],before[2]+[(2,5)])
  self.assertEqual(len(before[2]),2)
  self.assertEqual(after[1],before[1])

 def test_reopen_keeps_commit_order(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('release',5,'A');self.reopen()
  self.pool.operate('acquire',7,'B',10)
  self.pool.operate('list',8)
  report=self.pool.attribute_flows([flow('f','192.0.2.1',0,8,8)])
  self.assertEqual(report['flows'][0]['segments'],[
   {'start':0,'end':5,'status':'owned','client':'A','bytes':5},
   {'start':5,'end':7,'status':'free','client':None,'bytes':2},
   {'start':7,'end':8,'status':'owned','client':'B','bytes':1}])
  self.assertEqual(report['snapshot_seq'],4)


class TinyModel:
 """Independent tick-expanding model; used only for small spans in tests.

 It records the committed lease state after every successful operation and
 answers ownership tick by tick with half-open intervals, sharing no code
 with the production attribution engine.
 """
 def __init__(self,coverage_start,hosts):
  self.coverage_start=coverage_start;self.hosts=hosts
  self.timeline=[]  # (now, {address: (client, expires)})
 def commit(self,now,state):
  self.timeline.append((now,dict(state)))
 def state_at(self,tick):
  if tick<self.coverage_start:return None
  current=None
  for now,state in self.timeline:
   if now<=tick:current=state
   else:break
  return current
 def segments(self,address,start,end):
  if address not in self.hosts:return [(start,end,'outside_pool',None)]
  result=[]
  for tick in range(start,end):
   state=self.state_at(tick)
   if state is None:cell=('unknown',None)
   elif address in state and state[address][1]>tick:cell=('owned',state[address][0])
   else:cell=('free',None)
   if result and result[-1][2:]==cell:result[-1]=(result[-1][0],tick+1)+cell
   else:result.append((tick,tick+1)+cell)
  return result


class ModelCrossCheck(HistoryBase):
 def build_model(self,coverage_start):
  # 192.0.2.0/29 usable hosts are .1 through .6.
  return TinyModel(coverage_start,set(range(3221225985,3221225991)))

 def test_random_operations_match_tick_model(self):
  rnd=random.Random(11)
  for trial in range(30):
   with self.subTest(trial=trial):
    path=Path(self.tmp.name)/f'model{trial}.sqlite'
    if path.exists():path.unlink()
    pool=Pool(path);pool.initialize('192.0.2.0/29')
    coverage=0 if trial%2 else 2
    if coverage:
     strip_history(pool)
     pool.operate('acquire',0,'PRE',1);pool.operate('list',0);pool.operate('list',coverage)
    else:pool.operate('acquire',0,'PRE',1);pool.operate('list',0)
    pool.enable_history()
    model=self.build_model(coverage)
    def snap():
     return {int(r[0]):(r[1],r[2]) for r in pool.db.execute('SELECT address,client,expires FROM leases')}
    model.commit(coverage,snap())
    now=coverage
    clients=['A','B','C']
    try:
     for step in range(12):
      now+=rnd.randint(0,2)
      kind=rnd.choice(['acquire','acquire','release','list','reconcile'])
      try:
       if kind=='acquire':pool.operate('acquire',now,rnd.choice(clients),rnd.randint(1,6))
       elif kind=='release':pool.operate('release',now,rnd.choice(clients))
       elif kind=='list':pool.operate('list',now)
       else:
        chosen=rnd.sample(clients,rnd.randint(0,3))
        pool.reconcile(now,[demand(c,rnd.randint(1,6),'192.0.2.0/29') for c in chosen],[])
      except ValueError:continue
      model.commit(now,snap())
     clock=pool.db.execute('SELECT clock FROM metadata').fetchone()[0]
     addresses=['192.0.2.1','192.0.2.4','192.0.2.6','198.51.100.1','192.0.2.0']
     requests=[]
     for i in range(4):
      start=rnd.randint(0,clock-1)
      requests.append(flow(f'f{i}',addresses[i%len(addresses)],start,clock,rnd.randint(0,50)))
     report=pool.attribute_flows(requests)
     for item,request in zip(report['flows'],requests):
      expected=model.segments(int(ipaddress.IPv4Address(request['address'])),request['start'],request['end'])
      got=[(s['start'],s['end'],s['status'],s['client']) for s in item['segments']]
      self.assertEqual(got,expected)
      self.assertEqual(sum(s['bytes'] for s in item['segments']),request['bytes'])
     self.assertEqual(sum(t['bytes'] for t in report['totals']),sum(r['bytes'] for r in requests))
    finally:pool.close()

 def test_sparse_span_of_a_trillion_ticks(self):
  # Sparse changes: never expand every tick; explicit long gaps must work.
  self.pool.enable_history()
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',500_000_000_000,'B',10)
  self.pool.operate('release',900_000_000_000,'B')
  report=self.attribute([flow('f','192.0.2.1',0,1_000_000_000_000,10**12)])
  self.assertEqual([(s['start'],s['end'],s['status'],s['client']) for s in report['flows'][0]['segments']],[
   (0,10,'owned','A'),(10,500_000_000_000,'free',None),
   (500_000_000_000,500_000_000_010,'owned','B'),
   (500_000_000_010,1_000_000_000_000,'free',None)])
  self.assertEqual(sum(s['bytes'] for s in report['flows'][0]['segments']),10**12)


class AttributeCli(HistoryBase):
 def run_cli(self,*args):
  return subprocess.run([sys.executable,'-m','ipv4_leases.admin','--db',str(self.path),*args],capture_output=True,text=True)

 def test_full_cli_round_trip(self):
  done=self.run_cli('history-enable');self.assertEqual(done.returncode,0,done.stderr)
  self.assertEqual(json.loads(done.stdout),{'cidr':'192.0.2.0/29','coverage_start':0,'clock':0,'snapshot_seq':0})
  self.assertEqual(self.run_cli('acquire','--now','0','--client','A','--ttl','10').returncode,0)
  self.assertEqual(self.run_cli('acquire','--now','4','--client','A','--ttl','2').returncode,0)
  self.assertEqual(self.run_cli('acquire','--now','8','--client','B','--ttl','18').returncode,0)
  self.assertEqual(self.run_cli('list','--now','12').returncode,0)
  source=Path(self.tmp.name)/'flows.json';raw=json.dumps({'flows':[flow('f','192.0.2.1',0,12,7)]}).encode();source.write_bytes(raw)
  output=Path(self.tmp.name)/'report.json'
  done=self.run_cli('attribute','--source',str(source),'--output',str(output))
  self.assertEqual(done.returncode,0,done.stderr)
  saved=json.loads(output.read_text());printed=json.loads(done.stdout)
  self.assertEqual(saved,printed);self.assertEqual(saved['source_sha256'],hashlib.sha256(raw).hexdigest())
  self.assertEqual(saved['flows'][0]['segments'],[
   {'start':0,'end':6,'status':'owned','client':'A','bytes':4},
   {'start':6,'end':8,'status':'free','client':None,'bytes':1},
   {'start':8,'end':12,'status':'owned','client':'B','bytes':2}])
  self.assertEqual((saved['cidr'],saved['coverage_start'],saved['clock'],saved['snapshot_seq']),
   ('192.0.2.0/29',0,12,4))
  api=self.pool.attribute_flows([flow('f','192.0.2.1',0,12,7)])
  saved.pop('source_sha256');self.assertEqual(saved,api)

 def test_installed_fixture_flow_file(self):
  self.run_cli('acquire','--now','0','--client','A','--ttl','10')
  self.run_cli('acquire','--now','4','--client','A','--ttl','2')
  self.run_cli('acquire','--now','8','--client','B','--ttl','18')
  self.run_cli('list','--now','12')
  output=Path(self.tmp.name)/'fixture-report.json'
  source=ROOT/'fixtures'/'flows.json'
  done=self.run_cli('attribute','--source',str(source),'--output',str(output))
  self.assertEqual(done.returncode,0,done.stderr)
  payload=json.loads(done.stdout)
  self.assertEqual(payload['source_sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
  self.assertEqual(payload['flows'][0]['segments'],[
   {'start':0,'end':6,'status':'owned','client':'A','bytes':4},
   {'start':6,'end':8,'status':'free','client':None,'bytes':1},
   {'start':8,'end':12,'status':'owned','client':'B','bytes':2}])

 def test_cli_requires_history(self):
  strip_history(self.pool)
  self.run_cli('acquire','--now','0','--client','A','--ttl','10')
  source=Path(self.tmp.name)/'flows.json';source.write_text(json.dumps({'flows':[]}))
  output=Path(self.tmp.name)/'report.json';output.write_text('old')
  done=self.run_cli('attribute','--source',str(source),'--output',str(output))
  self.assertEqual(done.returncode,2);self.assertEqual(done.stdout,'');self.assertIn('history not enabled',done.stderr)
  self.assertEqual(output.read_text(),'old')

 def test_cli_rejects_bad_names_and_paths(self):
  self.run_cli('history-enable')
  source=Path(self.tmp.name)/'flows.json';source.write_text(json.dumps({'flows':[]}))
  output=Path(self.tmp.name)/'report.json';output.write_text('old')
  bad=[
   ('--source',str(source),'--output',str(source)),
   ('--source',str(source),'--output',str(self.path)),
   ('--source',str(self.path),'--output',str(output)),
  ]
  for args in bad:
   done=self.run_cli('attribute',*args)
   self.assertEqual(done.returncode,2);self.assertEqual(done.stdout,'')
  link=Path(self.tmp.name)/'link.json';link.symlink_to(output)
  done=self.run_cli('attribute','--source',str(source),'--output',str(link))
  self.assertEqual(done.returncode,2);self.assertEqual(output.read_text(),'old')
  self.assertEqual(source.read_text(),json.dumps({'flows':[]}))

 def test_cli_rejects_extra_fields_and_duplicate_keys(self):
  self.run_cli('history-enable')
  output=Path(self.tmp.name)/'report.json';output.write_text('old')
  for text in ['{"flows":[],"x":1}','{"flows":[],"flows":[]}',
               '{"flows":[{"id":"a","address":"192.0.2.1","start":0,"end":1,"bytes":1,"extra":2}]}']:
   source=Path(self.tmp.name)/'bad.json';source.write_text(text)
   done=self.run_cli('attribute','--source',str(source),'--output',str(output))
   self.assertEqual(done.returncode,2,text);self.assertEqual(output.read_text(),'old')

 def test_old_operations_still_work_on_legacy_database(self):
  self.pool.close();self.tmp.cleanup()
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'legacy.sqlite'
  args=[sys.executable,'-m','ipv4_leases.admin','--db',str(self.path)]
  self.assertEqual(subprocess.run(args+['init','--cidr','192.0.2.0/30'],capture_output=True).returncode,0)
  raw=sqlite3.connect(self.path)
  for name in ('history_changes','history_events','history_meta'):raw.execute(f'DROP TABLE {name}')
  raw.commit();raw.close()
  out=subprocess.run(args+['acquire','--now','0','--client','A','--ttl','10'],capture_output=True,text=True)
  self.assertEqual(out.returncode,0,out.stderr);self.assertEqual(json.loads(out.stdout)['leases'][0]['client'],'A')
  out=subprocess.run(args+['list','--now','5'],capture_output=True,text=True)
  self.assertEqual(out.returncode,0,out.stderr)
  out=subprocess.run(args+['history-enable'],capture_output=True,text=True)
  self.assertEqual(json.loads(out.stdout),{'cidr':'192.0.2.0/30','coverage_start':5,'clock':5,'snapshot_seq':0})


from fractions import Fraction
from ipv4_leases.attribution import MAX_BYTES, _allocate

class Apportionment(unittest.TestCase):
 def reference(self,segments,total,duration):
  shares=[Fraction(total*(b-a),duration) for a,b,*_ in segments]
  allocated=[int(share) for share in shares]
  extra=total-sum(allocated)
  remainders=[share-allocated[i] for i,share in enumerate(shares)]
  order=sorted(range(len(segments)),key=lambda i:(-remainders[i],segments[i][0]))
  for i in order[:extra]:allocated[i]+=1
  return allocated

 def test_random_segment_lengths_conserve_and_match_fractions(self):
  rnd=random.Random(5)
  for trial in range(500):
   count=rnd.randint(1,8)
   cuts=sorted(rnd.sample(range(1,200),count-1))
   bounds=[0]+cuts+[200]
   segments=[(bounds[i],bounds[i+1],'owned' if i%2 else 'free',None) for i in range(count)]
   total=rnd.choice([0,1,rnd.randint(0,10**18),MAX_BYTES])
   with self.subTest(trial=trial):
    got=_allocate(segments,200,total)
    self.assertEqual(got,self.reference(segments,total,200))
    self.assertEqual(sum(got),total)


class FlowLimits(HistoryBase):
 def test_accepts_exactly_10000_flows(self):
  self.pool.enable_history();self.pool.operate('list',3)
  flows=[flow(f'f{i:05d}','192.0.2.1',0,3,1) for i in range(10000)]
  report=self.pool.attribute_flows(flows)
  self.assertEqual(len(report['flows']),10000)
  self.assertEqual(sum(t['bytes'] for t in report['totals']),10000)
  self.assertEqual(report['flows'][0]['id'],'f00000')

 def test_duplicate_ids_and_off_by_one_time_rejected(self):
  self.pool.enable_history();self.pool.operate('list',3)
  with self.assertRaisesRegex(ValueError,'duplicate flow id'):
   self.pool.attribute_flows([flow('a','192.0.2.1',0,3,1),flow('a','192.0.2.2',0,3,1)])
  self.assertEqual(self.pool.attribute_flows([flow('a','192.0.2.1',0,3,1)])['flows'][0]['end'],3)
  with self.assertRaises(ValueError):self.pool.attribute_flows([flow('a','192.0.2.1',0,4,1)])


if __name__=='__main__':unittest.main()
