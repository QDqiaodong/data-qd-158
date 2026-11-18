import itertools,json,random,subprocess,sys,tempfile,unittest,concurrent.futures
from pathlib import Path
from ipv4_leases.pool import Pool,network
from ipv4_leases.reconcile import plan,parse_request

def demand(client,ttl,*allowed):return {'client':client,'ttl':ttl,'allowed':list(allowed)}

def brute(net,demands,blocked_ranges,old_active):
    lo,hi=int(net.network_address),int(net.broadcast_address)
    if net.prefixlen<=30:lo,hi=lo+1,hi-1
    usable=set(range(lo,hi+1));blocked=set()
    for a,b in blocked_ranges:blocked|=set(range(a,b+1))
    candidates=[]
    for client,_,ranges in demands:
        allowed=set()
        for a,b in ranges:allowed|=set(range(a,b+1))
        candidates.append(sorted(allowed&usable-blocked))
    clients=[c for c,_,_ in demands]
    order=sorted(range(len(clients)),key=lambda i:clients[i])
    best=None
    for combo in itertools.product(*candidates):
        if len(set(combo))<len(clients):continue
        allocation=dict(zip(clients,combo))
        moved=sum(1 for c in old_active if c in allocation and allocation[c]!=old_active[c])
        vector=tuple(allocation[clients[i]] for i in order)
        key=(moved,vector)
        if best is None or key<best[0]:best=(key,allocation)
    return best

class Reconciler(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'pool.sqlite'
  self.pool=Pool(self.path);self.pool.initialize('192.0.2.0/29')
 def tearDown(self):self.pool.close();self.tmp.cleanup()
 def rows(self):return self.pool.db.execute('SELECT client,address,expires FROM leases ORDER BY client').fetchall()

 def test_swap_two_active_clients(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  result=self.pool.reconcile(1,[demand('A',5,'192.0.2.1/32','192.0.2.2/32'),demand('B',5,'192.0.2.1/32')],[])
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],[('B','192.0.2.1'),('A','192.0.2.2')])
  self.assertEqual(result['moved_clients'],['A','B'])
  self.assertEqual(result['clock'],1);self.assertEqual([x['expires'] for x in result['leases']],[6,6])

 def test_infeasible_rolls_back_everything(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  self.pool.operate('acquire',0,'EXPIRED',1)
  with self.assertRaisesRegex(ValueError,'no complete allocation'):
   self.pool.reconcile(5,[demand('A',5,'192.0.2.1/32','192.0.2.2/32'),demand('B',5,'192.0.2.1/32'),demand('C',5,'192.0.2.1/32')],[])
  # Expiry cleanup and the clock roll back with the leases.
  self.assertEqual(self.rows(),[('A',3221225985,10),('B',3221225986,10),('EXPIRED',3221225987,1)])
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],0)

 def test_success_cleans_expired_and_resets_expiry(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'EXPIRED',1)
  result=self.pool.reconcile(5,[demand('A',7,'192.0.2.1/32')],[])
  self.assertEqual(result['leases'],[{'client':'A','address':'192.0.2.1','expires':12}])
  self.assertEqual([r[0] for r in self.rows()],['A'])

 def test_two_level_objective_and_order_invariance(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  d=[demand('A',5,'192.0.2.3/32','192.0.2.4/32'),demand('B',5,'192.0.2.3/32','192.0.2.4/32')]
  first=self.pool.reconcile(1,d,[])
  self.assertEqual([(x['client'],x['address']) for x in first['leases']],[('A','192.0.2.3'),('B','192.0.2.4')])
  self.assertEqual(first['moved_clients'],['A','B'])
  second=self.pool.reconcile(2,[demand('B',5,'192.0.2.4/32','192.0.2.3/32'),demand('A',5,'192.0.2.4/32','192.0.2.3/32')],[])
  self.assertEqual([(x['client'],x['address']) for x in second['leases']],[('A','192.0.2.3'),('B','192.0.2.4')])
  # The result is already canonical, so no client has to move again.
  self.assertEqual(second['moved_clients'],[])

 def test_order_invariance_from_independent_state(self):
  def fresh(index):
   pool=Pool(Path(self.tmp.name)/f'order{index}.sqlite');pool.initialize('192.0.2.0/29')
   pool.operate('acquire',0,'A',10);pool.operate('acquire',0,'B',10)
   return pool
  left,right=fresh(1),fresh(2)
  try:
   a=left.reconcile(1,[demand('A',5,'192.0.2.4/30','192.0.2.5/32'),demand('B',5,'192.0.2.4/31','192.0.2.5/32')],['192.0.2.7/32'])
   b=right.reconcile(1,[demand('B',5,'192.0.2.5/32','192.0.2.4/31'),demand('A',5,'192.0.2.4/30','192.0.2.5/32')],['192.0.2.7/32','192.0.2.7/32'])
   self.assertEqual(a,b)
  finally:left.close();right.close()

 def test_zero_moves_beats_smaller_addresses(self):
  # Establish the non-canonical but zero-move-friendly state B=.1, A=.2.
  self.pool.reconcile(0,[demand('A',10,'192.0.2.2/32'),demand('B',10,'192.0.2.1/32')],[])
  self.assertEqual({x['client']:x['address'] for x in self.pool.operate('list',0)['leases']},{'A':'192.0.2.2','B':'192.0.2.1'})
  result=self.pool.reconcile(1,[demand('A',5,'192.0.2.1/32','192.0.2.2/32'),demand('B',5,'192.0.2.1/32','192.0.2.2/32')],[])
  # A=.1/B=.2 is lexicographically smaller, but would move both clients.
  self.assertEqual({x['client']:x['address'] for x in result['leases']},{'A':'192.0.2.2','B':'192.0.2.1'})
  self.assertEqual(result['moved_clients'],[])

 def test_zero_move_preferred_and_sorted_clients(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  result=self.pool.reconcile(1,[demand('B',5,'192.0.2.1/32','192.0.2.2/32','192.0.2.3/32'),demand('A',5,'192.0.2.1/32','192.0.2.2/32')],[])
  self.assertEqual(result['moved_clients'],[])
  # Zero moves beats the lexicographically smaller A=.1/B=.2 alternative.
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],[('A','192.0.2.1'),('B','192.0.2.2')])

 def test_deleted_and_expired_clients_do_not_count_as_moved(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  self.pool.operate('acquire',0,'GONE',10);self.pool.operate('acquire',0,'OLD',1)
  result=self.pool.reconcile(5,[demand('A',5,'192.0.2.1/32','192.0.2.2/32'),demand('C',5,'192.0.2.1/32')],[])
  # C can only take .1, so A (formerly .1) is the sole moved client; the
  # deleted GONE and the expired OLD never count.
  self.assertEqual(result['moved_clients'],['A'])
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],[('C','192.0.2.1'),('A','192.0.2.2')])
  self.assertEqual(self.pool.db.execute("SELECT COUNT(*) FROM leases WHERE client IN ('GONE','OLD')").fetchone()[0],0)

 def test_expiry_at_now_is_not_live(self):
  self.pool.operate('acquire',0,'A',5)
  result=self.pool.reconcile(5,[demand('A',5,'192.0.2.2/32')],[])
  self.assertEqual(result['leases'][0]['address'],'192.0.2.2');self.assertEqual(result['moved_clients'],[])

 def test_empty_demands_clears_pool(self):
  self.pool.operate('acquire',0,'A',10)
  result=self.pool.reconcile(1,[],[])
  self.assertEqual(result['leases'],[]);self.assertEqual(result['moved_clients'],[])
  self.assertEqual(self.rows(),[]);self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],1)

 def test_overlapping_and_blocked_cidrs(self):
  result=self.pool.reconcile(0,[demand('A',5,'192.0.2.0/30','192.0.2.2/31'),demand('B',5,'192.0.2.0/29')],['192.0.2.1/32','192.0.2.3/32'])
  # A can only use .0-.3 (network .0 and blocked .1/.3 leave .2); B takes .4.
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],[('A','192.0.2.2'),('B','192.0.2.4')])

 def test_clock_backwards_rolls_back(self):
  self.pool.operate('list',10)
  with self.assertRaisesRegex(ValueError,'clock cannot move backward'):
   self.pool.reconcile(9,[],[])
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],10)

 def test_validation_rejects_bad_requests(self):
  bad=[
   (0,[{'client':'A','ttl':1,'allowed':['192.0.2.1/32'],'x':1}],[]),
   (0,[{'client':'A','ttl':1,'allowed':['192.0.2.1/32']},{'client':'A','ttl':1,'allowed':['192.0.2.2/32']}],[]),
   (0,[{'client':'A','ttl':True,'allowed':['192.0.2.1/32']}],[]),
   (0,[{'client':'A','ttl':1,'allowed':[]}],[]),
   (0,[{'client':'A','ttl':1,'allowed':['192.0.2.1/24']}],[]),
   (0,[{'client':'A','ttl':1,'allowed':['2001:db8::/32']}],[]),
   (0,[{'client':'A','ttl':1,'allowed':['192.0.2.1/32']}],['192.0.2.1/32','192.0.2.1/32']*65),
   (True,[],[]),
  ]
  for now,demands,blocked in bad:
   with self.subTest(now=now,demands=demands),self.assertRaises(ValueError):self.pool.reconcile(now,demands,blocked)
  self.assertEqual(self.rows(),[])

 def test_slash31_and_slash32_pools(self):
  for index,cidr,use in [(1,'192.0.2.0/31','192.0.2.1/32'),(2,'192.0.2.9/32','192.0.2.9/32')]:
   p=Pool(Path(self.tmp.name)/f'small{index}.sqlite')
   try:
    p.initialize(cidr)
    result=p.reconcile(0,[demand('A',5,use)],[])
    self.assertEqual(result['leases'][0]['address'],use.split('/')[0])
    if cidr=='192.0.2.0/31':
     # Zero-move preference keeps the live .1 even though .0 is smaller.
     self.assertEqual([x['address'] for x in p.reconcile(1,[demand('A',5,'192.0.2.0/31')],[])['leases']],['192.0.2.1'])
     self.assertEqual([x['address'] for x in p.reconcile(2,[demand('Z',5,'192.0.2.0/31')],[])['leases']],['192.0.2.0'])
   finally:p.close()

 def test_chain_requires_global_rearrangement(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  result=self.pool.reconcile(1,[demand('A',5,'192.0.2.2/32'),demand('B',5,'192.0.2.1/32')],[])
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],[('B','192.0.2.1'),('A','192.0.2.2')])
  self.assertEqual(result['moved_clients'],['A','B'])

 def test_chain_forces_changing_earlier_choice(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  # Keeping A on .1 (its zero-move choice) would leave C, which only allows
  # .1, unassigned; the minimum-move solution gives C .1, keeps B on .2 and
  # moves only A to .3.
  result=self.pool.reconcile(1,[
   demand('A',5,'192.0.2.1/32','192.0.2.3/32'),
   demand('B',5,'192.0.2.1/32','192.0.2.2/32'),
   demand('C',5,'192.0.2.1/32'),
  ],[])
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],
   [('C','192.0.2.1'),('B','192.0.2.2'),('A','192.0.2.3')])
  self.assertEqual(result['moved_clients'],['A'])

 def test_cli_reconcile_and_failure(self):
  args=[sys.executable,'-m','ipv4_leases.admin','--db',str(self.path)]
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  source=Path(self.tmp.name)/'request.json'
  source.write_text(json.dumps({'now':1,'demands':[demand('A',5,'192.0.2.1/32','192.0.2.2/32'),demand('B',5,'192.0.2.1/32')],'blocked':[]}))
  done=subprocess.run(args+['reconcile','--source',str(source)],capture_output=True,text=True)
  self.assertEqual(done.returncode,0,done.stderr)
  payload=json.loads(done.stdout);self.assertEqual(payload['moved_clients'],['A','B']);self.assertEqual(payload['leases'][0]['address'],'192.0.2.1')
  bad=Path(self.tmp.name)/'bad.json'
  bad.write_text(json.dumps({'now':2,'demands':[demand('A',5,'192.0.2.1/32'),demand('B',5,'192.0.2.1/32')],'blocked':[]}))
  failed=subprocess.run(args+['reconcile','--source',str(bad)],capture_output=True,text=True)
  self.assertEqual(failed.returncode,2);self.assertEqual(failed.stdout,'');self.assertIn('no complete allocation',failed.stderr)
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],1)

 def test_invalid_json_file_rolls_back(self):
  source=Path(self.tmp.name)/'dup.json';source.write_text('{"now":1,"now":2,"demands":[],"blocked":[]}')
  failed=subprocess.run([sys.executable,'-m','ipv4_leases.admin','--db',str(self.path),'reconcile','--source',str(source)],capture_output=True,text=True)
  self.assertEqual(failed.returncode,2);self.assertEqual(failed.stdout,'')

 def test_installed_fixture(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  fixture=Path(__file__).resolve().parents[1]/'fixtures'/'reconcile.json'
  done=subprocess.run([sys.executable,'-m','ipv4_leases.admin','--db',str(self.path),'reconcile','--source',str(fixture)],capture_output=True,text=True)
  self.assertEqual(done.returncode,0,done.stderr)
  payload=json.loads(done.stdout)
  self.assertEqual(payload['moved_clients'],['A','B'])
  self.assertEqual([(x['client'],x['address']) for x in payload['leases']],[('B','192.0.2.1'),('A','192.0.2.2')])

 def test_concurrent_reconcile_and_acquire_serialise(self):
  def work(index):
   p=Pool(self.path)
   try:
    if index%2:return p.reconcile(0,[demand(f'R{index}',10,'192.0.2.0/29')],[])
    return p.operate('acquire',0,f'Q{index}',10)
   finally:p.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
   list(pool.map(work,range(4)))
  self.assertLessEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],6)

 def test_moved_clients_sorted_by_python_string_order(self):
  self.pool.operate('acquire',0,'b',10);self.pool.operate('acquire',0,'A',10)
  result=self.pool.reconcile(1,[demand('A',5,'192.0.2.4/32'),demand('b',5,'192.0.2.3/32')],[])
  self.assertEqual(result['moved_clients'],['A','b'])
  self.assertEqual([(x['client'],x['address']) for x in result['leases']],[('b','192.0.2.3'),('A','192.0.2.4')])

 def test_dense_128_clients_shared_slash24(self):
  p=Pool(Path(self.tmp.name)/'dense.sqlite');p.initialize('198.51.100.0/24')
  try:
   demands=[demand(f'c{i:03d}',7,'198.51.100.0/24') for i in range(128)]
   result=p.reconcile(0,demands,[])
   self.assertEqual(len(result['leases']),128)
   addresses={x['client']:x['address'] for x in result['leases']}
   self.assertEqual(len(set(addresses.values())),128)
   self.assertEqual(addresses['c000'],'198.51.100.1')
   self.assertEqual(addresses['c127'],'198.51.100.128')
   self.assertEqual(result['moved_clients'],[])
  finally:p.close()

 def test_exhaustive_small_pool_matches_bruteforce(self):
  rnd=random.Random(7)
  for seed in range(120):
   net=network('198.51.100.0/29')
   lo,hi=int(net.network_address)+1,int(net.broadcast_address)-1
   usable=list(range(lo,hi+1))
   old={f'O{i}':rnd.choice(usable) for i in range(rnd.randint(0,3))}
   demands=[]
   for i in range(rnd.randint(0,4)):
    picked=sorted(rnd.sample(usable,rnd.randint(1,len(usable))))
    demands.append((f'C{i}',5,[(a,a) for a in picked]))
   blocked=[(a,a) for a in usable if rnd.random()<0.2]
   with self.subTest(seed=seed):
    best=brute(net,demands,blocked,old)
    try:got=plan(net,demands,blocked,old)
    except ValueError:got=None
    if best is None:
     self.assertIsNone(got);continue
    self.assertIsNotNone(got)
    key,allocation=best
    clients=[c for c,_,_ in demands]
    moved=sum(1 for c in old if c in got and got[c]!=old[c])
    vector=tuple(got[clients[i]] for i in sorted(range(len(clients)),key=lambda i:clients[i]))
    self.assertEqual((moved,vector),key)


class ParseContract(unittest.TestCase):
 def test_parse_normalises_and_limits(self):
  now,demands,blocked=parse_request(3,[{'client':'A','ttl':2,'allowed':['0.0.0.0/0']}],['10.0.0.0/8'])
  self.assertEqual(now,3);self.assertEqual(demands,[('A',2,[(0,2**32-1)])]);self.assertEqual(blocked,[(167772160,184549375)])
 def test_limits(self):
  with self.assertRaises(ValueError):parse_request(0,[{'client':f'C{i}','ttl':1,'allowed':['0.0.0.0/0']} for i in range(129)],[])
  with self.assertRaises(ValueError):parse_request(0,[{'client':'A','ttl':1,'allowed':['0.0.0.0/0']*33}],[])
  with self.assertRaises(ValueError):parse_request(0,[],[f'10.0.0.{i}/32' for i in range(129)])
 def test_bad_identifiers_and_bools(self):
  for bad in ['', ' x', 'x ', 'x'*129, 1, None]:
   with self.subTest(bad=bad),self.assertRaises(ValueError):parse_request(0,[{'client':bad,'ttl':1,'allowed':['0.0.0.0/0']}],[])
  with self.assertRaises(ValueError):parse_request(0,[{'client':'A','ttl':1.0,'allowed':['0.0.0.0/0']}],[])
  with self.assertRaises(ValueError):parse_request(0,[{'client':'A','ttl':1,'allowed':['0.0.0.0/0','::/0']}],[])
