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

## 离线DHCP外部占用采集

把抓包文件中的有效DHCPACK转为有期限的外部地址占用，使本池不再把这些地址分给本地租约。全程只读文件与SQLite，不接触真实网络：

```sh
.venv/bin/ipv4-admin --db run/pool.sqlite import-dhcp --now 8 --source capture.pcap
```

对应API为`Pool.import_dhcp(now, capture_path)`。输入仅支持经典PCAP v2.4（大/小端微秒时间戳、linktype=Ethernet(1)、≤8MB），拒绝pcapng与纳秒格式；逐字节校验24字节全局头与16字节记录头及记录边界（snaplen 1..262144，`0<incl_len=orig_len<=snaplen`，usec 0..999999，秒数0..now）。时间戳不要求按文件顺序递增；秒数直接作为本池tick，微秒仅校验范围、不参与TTL。

链路/IP/UDP/DHCP各层严格校验：仅处理EtherType=0x0800、protocol=17且version=4、IHL=5、头校验和正确的IPv4帧（DF不得与MF或非零offset同现，保留flag须为0）；按`(src,dst,protocol,id)`跨帧乱序、交错重组UDP数据报，支持字节相同的重复/交叠分片。重叠字节不一致、终片长度矛盾、缺零偏移片、缺终片或留洞都使**整次导入失败**，即使此前已拼出完整报文。每组`observed_at`取所有零偏移片中最早的捕获秒数；未分片报文走相同一致性规则。重组报文须为67→68端口的DHCPACK（option 53跨全部已选区域恰出现一次且长度1；ACK须op=2、htype=1、hlen=6，option 51/54各恰一次且长度4，51为1..10^9网络序TTL，54为非零server，yiaddr非零，mac取chaddr前6字节规范为小写冒号）；支持option 52（值1/2/3）的file/sname过载，52只可在主options出现一次；非ACK、其他端口与非目标帧一律忽略，坏IP/UDP校验和拒绝整次导入。

每条事实以五元组`(server,mac,address,observed_at,ttl)`标识，`expires=observed_at+ttl`（零偏移分片最早捕获秒数加option 51秒数，而非导入now加TTL）；仅保留`expires>now`的事实，重复导入同一五元组不累加、不延长，到期后重导不复活，不同server或mac对同地址的宣告各自独立保留。yiaddr不属于本池可用hosts（沿用/20../30及/31、/32的hosts语义）的ACK忽略。旧库在第一次`import-dhcp`时才显式建立`external_dhcp_claims`表，旧命令不依赖该表；导入不会替旧库启用归属历史，`attribute_flows`仍为只读、不清理或写入外部事实，也不把第三方宣告当作本地持有者；只有确认外部表不存在时才视为空集合，其他SQL错误照常抛出。

整个导入在一次`BEGIN IMMEDIATE`内拒绝时钟倒退、清理到期本地租约与外部事实、写入本次仍有效事实、推进clock，并在已启用历史时追加一条post-state历史事件；任何解析、校验或写入错误都整体回滚（租约、外部事实、clock、历史序号均不变）。外部占用不驱逐现存本地租约，但在`conflicts`中报告同地址的活跃client与全部外部事实，也不把本地client与mac自动视作同一主体。`acquire`活跃client续租撞上外部占用直接失败（不偷偷换址），新client取满足排除条件的最小空闲地址；`reconcile`仍以原权威demands与原两级全局目标求解，仅在实际候选中（同事务内把每个外部地址作为/32并入blocked）排除外部占用，不可行时连过期清理一起回滚，`moved_clients`定义不变。`release/list`沿用原规则并随事务清理到期外部事实；无外部占用时旧分配目标、返回结构、历史归属与JSON演示结果保持兼容。

成功stdout输出JSON并退出0，字段为`cidr`、`clock`、`leases`（原结构、按地址排序）、`claims`、`conflicts`、`source_sha256`（捕获文件原字节SHA256，事实身份不依赖文件路径或摘要）。`claims`列出提交后全部活跃外部事实，每项含`server`、`mac`、`address`、`observed_at`、`ttl`、`expires`，按`(address数值,server数值,mac,observed_at,ttl)`排序；`conflicts`每项为`address`、`client`、`claims`，按address数值排序，内层`claims`沿用同一排序，无冲突为空数组。出错退出2、只写stderr、不输出成功JSON；拒绝source/database同路径及符号链接source或database。
