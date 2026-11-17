import argparse,json,sqlite3,sys
from pathlib import Path
from .pool import Pool

def main():
    p=argparse.ArgumentParser(description='Local IPv4 lease administrator')
    p.add_argument('--db',type=Path,required=True);sub=p.add_subparsers(dest='op',required=True)
    init=sub.add_parser('init');init.add_argument('--cidr',required=True)
    for kind in ('acquire','release','list'):
        q=sub.add_parser(kind);q.add_argument('--now',type=int,required=True)
        if kind!='list':q.add_argument('--client',required=True)
        if kind=='acquire':q.add_argument('--ttl',type=int,required=True)
    args=p.parse_args();pool=None
    try:
        if args.db.is_symlink():raise ValueError('symlink database rejected')
        if args.op!='init' and not args.db.is_file():raise ValueError('database missing; initialize first')
        pool=Pool(args.db)
        out=pool.initialize(args.cidr) if args.op=='init' else pool.operate(args.op,args.now,getattr(args,'client',None),getattr(args,'ttl',None))
        print(json.dumps(out,sort_keys=True));return 0
    except (OSError,ValueError,sqlite3.Error) as e:print(str(e),file=sys.stderr);return 2
    finally:
        if pool:pool.close()
if __name__=='__main__':raise SystemExit(main())
