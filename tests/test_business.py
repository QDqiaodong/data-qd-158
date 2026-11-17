import unittest,tempfile,sqlite3,subprocess,sys,json,concurrent.futures
from pathlib import Path
from ipv4_leases.pool import Pool
class Leases(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'pool.sqlite';self.pool=Pool(self.path);self.pool.initialize('192.0.2.0/30')
 def tearDown(self):self.pool.close();self.tmp.cleanup()
 def test_smallest_and_renew(self):
  self.pool.operate('acquire',0,'A',10);r=self.pool.operate('acquire',1,'A',20);self.assertEqual(r['leases'],[{'client':'A','address':'192.0.2.1','expires':21}])
 def test_exact_expiry_reuse(self):
  self.pool.operate('acquire',0,'A',10);r=self.pool.operate('acquire',10,'B',5);self.assertEqual(r['leases'][0]['address'],'192.0.2.1');self.assertEqual(len(r['leases']),1)
 def test_exhaustion_rolls_back_clock(self):
  self.pool.operate('acquire',0,'A',10);self.pool.operate('acquire',0,'B',10)
  with self.assertRaisesRegex(ValueError,'exhausted'):self.pool.operate('acquire',5,'C',10)
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],0);self.assertEqual(len(self.pool.operate('list',0)['leases']),2)
 def test_clock_backwards_rollback(self):
  self.pool.operate('list',10)
  with self.assertRaises(ValueError):self.pool.operate('list',9)
  self.assertEqual(self.pool.db.execute('SELECT clock FROM metadata').fetchone()[0],10)
 def test_release_missing_and_live(self):
  self.pool.operate('acquire',0,'A',10);self.assertEqual(self.pool.operate('release',0,'A')['leases'],[]);self.assertEqual(self.pool.operate('release',0,'A')['leases'],[])
 def test_cidr_init_no_reconfigure(self):
  with self.assertRaises(ValueError):self.pool.initialize('192.0.3.0/30')
  self.assertEqual(self.pool.initialize('192.0.2.0/30')['usable'],2)
 def test_ipv6_and_hostbits_rejected(self):
  for cidr in ['::1/128','192.0.2.1/24','10.0.0.0/8']:
   with self.subTest(cidr=cidr),self.assertRaises(ValueError):self.pool.initialize(cidr)
 def test_slash31_32(self):
  for index,cidr,capacity in [(1,'192.0.2.0/31',2),(2,'192.0.2.8/32',1)]:
   p=Pool(Path(self.tmp.name)/f'{index}.sqlite')
   try:self.assertEqual(p.initialize(cidr)['usable'],capacity)
   finally:p.close()
 def test_persistence_cli(self):
  args=[sys.executable,'-m','ipv4_leases.admin','--db',str(self.path)]
  c=subprocess.run(args+['acquire','--now','0','--client','A','--ttl','10'],capture_output=True,text=True);self.assertEqual(c.returncode,0,c.stderr)
  c=subprocess.run(args+['list','--now','1'],capture_output=True,text=True);self.assertEqual(json.loads(c.stdout)['leases'][0]['client'],'A')
 def test_concurrent_connections_unique(self):
  def acquire(client):
   p=Pool(self.path)
   try:return p.operate('acquire',0,client,10)
   finally:p.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(acquire,['A','B']))
  leases=self.pool.operate('list',0)['leases'];self.assertEqual(len({x['address'] for x in leases}),2)
