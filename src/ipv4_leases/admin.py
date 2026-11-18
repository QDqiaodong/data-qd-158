import argparse,json,sqlite3,sys
from pathlib import Path
from .common import read,require,save
from .pool import Pool

def _conflict(paths):
    resolved=[p.resolve() for p in paths]
    if len(set(resolved))!=len(resolved):raise ValueError('source, output and database paths must differ')

def main():
    p=argparse.ArgumentParser(description='Local IPv4 lease administrator')
    p.add_argument('--db',type=Path,required=True);sub=p.add_subparsers(dest='op',required=True)
    init=sub.add_parser('init');init.add_argument('--cidr',required=True)
    for kind in ('acquire','release','list'):
        q=sub.add_parser(kind);q.add_argument('--now',type=int,required=True)
        if kind!='list':q.add_argument('--client',required=True)
        if kind=='acquire':q.add_argument('--ttl',type=int,required=True)
    rec=sub.add_parser('reconcile');rec.add_argument('--source',type=Path,required=True)
    imp=sub.add_parser('import-dhcp');imp.add_argument('--now',type=int,required=True);imp.add_argument('--source',type=Path,required=True)
    sub.add_parser('history-enable')
    att=sub.add_parser('attribute');att.add_argument('--source',type=Path,required=True);att.add_argument('--output',type=Path,required=True)
    rim=sub.add_parser('route-impact');rim.add_argument('--source',type=Path,required=True);rim.add_argument('--output',type=Path,required=True)
    acl=sub.add_parser('acl-diff');acl.add_argument('--source',type=Path,required=True);acl.add_argument('--output',type=Path,required=True)
    args=p.parse_args();pool=None
    try:
        if args.db.is_symlink():raise ValueError('symlink database rejected')
        if args.op!='init' and not args.db.is_file():raise ValueError('database missing; initialize first')
        request=None
        if args.op in ('reconcile','attribute','route-impact','acl-diff'):
            if args.op=='reconcile':
                request,_=read(args.source);require(request,'now demands blocked')
            elif args.op=='attribute':
                _conflict([args.source,args.output,args.db])
                request,digest=read(args.source);require(request,'flows')
            elif args.op=='acl-diff':
                if args.source.is_symlink():raise ValueError('symlink ACL source rejected')
                if args.output.is_symlink():raise ValueError('symlink output rejected')
                _conflict([args.source,args.output,args.db])
                if not args.source.is_file():raise ValueError('ACL source missing')
                request,digest=read(args.source);require(request,'before after')
            else:
                if args.source.is_symlink():raise ValueError('symlink route source rejected')
                if args.output.is_symlink():raise ValueError('symlink output rejected')
                _conflict([args.source,args.output,args.db])
                if not args.source.is_file():raise ValueError('route source missing')
                request,digest=read(args.source);require(request,'routes scenarios')
        elif args.op=='import-dhcp':
            if args.source.is_symlink():raise ValueError('symlink capture source rejected')
            _conflict([args.source,args.db])
            if not args.source.is_file():raise ValueError('capture source missing')
        pool=Pool(args.db)
        if args.op=='init':out=pool.initialize(args.cidr)
        elif args.op=='reconcile':out=pool.reconcile(request['now'],request['demands'],request['blocked'])
        elif args.op=='import-dhcp':out=pool.import_dhcp(args.now,args.source)
        elif args.op=='history-enable':out=pool.enable_history()
        elif args.op=='attribute':
            out=pool.attribute_flows(request['flows']);out['source_sha256']=digest;save(args.output,out)
        elif args.op=='route-impact':
            out=pool.route_impact(request['routes'],request['scenarios']);out['source_sha256']=digest;save(args.output,out)
        elif args.op=='acl-diff':
            out=pool.acl_diff(request['before'],request['after']);out['source_sha256']=digest;save(args.output,out)
        else:out=pool.operate(args.op,args.now,getattr(args,'client',None),getattr(args,'ttl',None))
        print(json.dumps(out,sort_keys=True));return 0
    except (OSError,ValueError,TypeError,KeyError,OverflowError,RecursionError,sqlite3.Error) as e:print(str(e),file=sys.stderr);return 2
    finally:
        if pool:pool.close()
if __name__=='__main__':raise SystemExit(main())
