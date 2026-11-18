# data-qd-158 · IPv4地址租约管理

Transactional bounded IPv4 lease allocation and expiry。业务输入、计算和当前边界详见 [数据契约](docs/contract.md)。

## 安装与演示

Python >=3.11，运行和测试仅用标准库；先确认 `python3 --version`。
每仓建立独立环境，构建工具锁版本。首次安装无公共缓存时可能联网；业务运行不访问网络。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-build.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps .
.venv/bin/python -m pip check
.venv/bin/ipv4-leases --source fixtures/input.json --output run/report.json
.venv/bin/python -m unittest discover -s tests -v
```

本地已有wheel时，安装构建工具可加 `--no-index --find-links <公共wheel缓存目录>`。
修改源码后重新安装。本仓不共享其他仓环境，不依赖Docker、外部账号或持续服务。

输入JSON最多8MB，拒绝重复键、非有限数值和未定义字段；源字节SHA256随结果保留。
输出是可独立读取的JSON；成功后原子替换，输入/计算失败退出2并保留旧报告。
输入和输出不得相同，输出符号链接拒绝。单操作者批处理，不承诺并发发布或断电恢复。
同输入重跑不累加。测试使用临时目录，运行产物在忽略的run/。

src/ipv4_leases/model.py 为业务模型，相关算法模块独立组织；common.py 提供受限JSON及报告发布，
cli.py 衔接数据链路。fixtures 为明确自制样例，代码与样例采用MIT许可。

## 业务与样例

# Exclusive IPv4 lease pool v1
本地地址管理员维护一个SQLite数据库对应一个严格CIDR IPv4 /20../32地址池。/20../30排除network/broadcast；/31两地址可用、/32单地址可用，采用Python ipaddress hosts语义。最多4094普通主机。不会配置网卡、发送DHCP或与真实网络交互。
独立持久入口：.venv/bin/ipv4-admin --db run/pool.sqlite init --cidr 192.0.2.0/30（先mkdir -p run）；随后acquire --now 0 --client A --ttl 10、list --now 10、release --now 10 --client A。数据库父目录须存在。init同CIDR幂等，异CIDR拒绝。
now为0..10^12逻辑整数tick，每次操作不得倒退；ttl=1..10^9，expires<=now先回收。acquire同活跃client续租原地址、expires重置为now+ttl；新client取最小空闲地址，release无记录正常。BEGIN IMMEDIATE、client主键及address唯一约束，耗尽/时钟错误整事务回滚，连过期清理和clock都不提交。list也会提交过期清理与clock。
JSON入口是隔离临时数据库中的可重现操作演示，输入cidr及operations，输出每次事务后的状态；实际跨命令持久化用ipv4-admin。样例A=.1到10、B=.2到20，10时C复用.1到15，20时空池。只保留当前租约及按需启用的归属历史（见下节），无请求回执/高可用/恶意文件并发替换沙箱；本地可信单数据库，SQLite协调连接并发。
一次性期望集合对账：.venv/bin/ipv4-admin --db run/pool.sqlite reconcile --source request.json，其中request.json严格为{"now":整数,"demands":[{"client":标识,"ttl":整数,"allowed":[CIDR,...]},...],"blocked":[CIDR,...]}。demands是事务后全部活跃client的权威集合，最多128个互异client，每项allowed为1..32个/0../32严格IPv4 CIDR，blocked至多128个。先在全部完整可行分配中最小化迁移client数，再在client字符串序下取地址向量字典序最小；结果与demands/CIDR排列无关，不枚举完整分配。成功输出含cidr、clock、按地址排序的leases及按client排序的moved_clients，退出0；非法或不可行退出2、不输出成功JSON、数据库保持不变。详见[数据契约](docs/contract.md)。

## 离线流量归属

启用历史（新池`init`时自动从clock=0开始；旧库须显式启用，只从启用时刻起记录，不倒推）：

```sh
.venv/bin/ipv4-admin --db run/pool.sqlite history-enable
```

成功返回cidr、coverage_start、clock、snapshot_seq。之后每次成功的acquire/release/list/reconcile在同一事务内追加一条连续seq历史；失败操作不留痕。启用不推进clock、不改租约；重复启用幂等。

按地址采样流量并归属到历史持有者：

```sh
.venv/bin/ipv4-admin --db run/pool.sqlite attribute --source flows.json --output report.json
```

flows.json严格为`{"flows":[{"id":"f1","address":"192.0.2.1","start":0,"end":12,"bytes":7},...]}`（≤10000条，8MB）。输出把每个flow切成覆盖`[start,end)`的最大连续段（owned/free/unknown/outside_pool），并按段时长比例用最大余数法精确分配整数字节。CLI在报告中附加`source_sha256`，stdout输出同一报告并原子写`--output`；出错退出2且保留旧报告。`Pool.attribute_flows(flows)`返回同一报告（无`source_sha256`），只读事务、不改clock/租约/历史。
