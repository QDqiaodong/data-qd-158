# Exclusive IPv4 lease pool v1
本地地址管理员维护一个SQLite数据库对应一个严格CIDR IPv4 /20../32地址池。/20../30排除network/broadcast；/31两地址可用、/32单地址可用，采用Python ipaddress hosts语义。最多4094普通主机。不会配置网卡、发送DHCP或与真实网络交互。
独立持久入口：.venv/bin/ipv4-admin --db run/pool.sqlite init --cidr 192.0.2.0/30（先mkdir -p run）；随后acquire --now 0 --client A --ttl 10、list --now 10、release --now 10 --client A。数据库父目录须存在。init同CIDR幂等，异CIDR拒绝。
now为0..10^12逻辑整数tick，每次操作不得倒退；ttl=1..10^9，expires<=now先回收。acquire同活跃client续租原地址、expires重置为now+ttl；新client取最小空闲地址，release无记录正常。BEGIN IMMEDIATE、client主键及address唯一约束，耗尽/时钟错误整事务回滚，连过期清理和clock都不提交。list也会提交过期清理与clock。
JSON入口是隔离临时数据库中的可重现操作演示，输入cidr及operations，输出每次事务后的状态；实际跨命令持久化用ipv4-admin。样例A=.1到10、B=.2到20，10时C复用.1到15，20时空池。只保留当前租约，无审计历史/请求回执/高可用/恶意文件并发替换沙箱；本地可信单数据库，SQLite协调连接并发。

## 一次性期望集合对账

`ipv4-admin --db DB reconcile --source FILE` 在池内重新安排整批租约；`Pool.reconcile(now, demands, blocked)` 为对应API。它不访问网络，`init/acquire/release/list` 与JSON演示入口的既有契约不变。

输入文件严格为 `{"now":整数,"demands":[{"client":标识,"ttl":整数,"allowed":[严格IPv4 CIDR,...]},...],"blocked":[严格IPv4 CIDR,...]}`，沿用8MB严格JSON读取与now/ttl/标识校验。最多128个互异client；每项`allowed`为1..32个CIDR；`blocked`至多128个。重复client、未定义字段、布尔整数、IPv6、host bits一律拒绝。CIDR可为/0../32，成员含其全部地址；实际候选还必须属于池的可用hosts、该client的allowed并集，且不在blocked并集内。

`demands` 是事务完成后全部活跃client的权威集合：未列出的原活跃client被删除，`expires<=now` 者不算原活跃，空`demands`合法并清空池。每个需求恰得一个互异地址，`expires=now+ttl`（按各自ttl重置）。原活跃指事务开始所读状态中`expires>now`；迁移只统计其中仍在`demands`且地址改变的client，新建、过期与被删除client都不计。

目标是两级全局最优：先最小化迁移client数；在该最优值内，把client按Python字符串排序后，用各自IPv4数值组成的地址向量取字典序最小。实现把两级目标编码为单一整数代价，用最小代价完美匹配（连续最短增广路）求解；每个client只保留其最小的n个可行地址及其原地址（n为需求数），已足以包含两级最优解，不枚举完整分配，也不依赖demands/CIDR的排列、重复或交叠。

对账在单次 `BEGIN IMMEDIATE` 中读取原租约与clock、拒绝now倒退、计算并写入全部新租约与clock。无完整分配或任何校验/写入错误时租约、过期清理和clock全部回滚；成功时可合法交换两个活跃client的地址而不触发address UNIQUE冲突。它与旧操作按同一SQLite串行顺序生效。

成功返回原有`cidr`、`clock`、按地址数值排序的`leases`，并额外返回按client排序的`moved_clients`。CLI成功输出该JSON并退出0；非法或不可行时退出2并向stderr说明原因，不输出成功JSON，数据库保持不变。
