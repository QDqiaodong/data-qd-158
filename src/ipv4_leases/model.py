from tempfile import TemporaryDirectory
from pathlib import Path
from .common import require,rows
from .pool import Pool

def analyze(data):
    require(data,'cidr operations')
    with TemporaryDirectory() as tmp:
        pool=Pool(Path(tmp)/'leases.sqlite');pool.initialize(data['cidr']);results=[]
        try:
            for op in rows(data['operations'],10000):
                if not isinstance(op,dict):raise ValueError('operation object required')
                kind=op.get('kind');require(op,{'acquire':'kind now client ttl','release':'kind now client','list':'kind now'}.get(kind,'invalid'))
                results.append(pool.operate(kind,op['now'],op.get('client'),op.get('ttl')))
        finally:pool.close()
    return {'operations':results}
