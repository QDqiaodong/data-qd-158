# Exclusive IPv4 lease pool v1
本地地址管理员维护一个SQLite数据库对应一个严格CIDR IPv4 /20../32地址池。/20../30排除network/broadcast；/31两地址可用、/32单地址可用，采用Python ipaddress hosts语义。最多4094普通主机。不会配置网卡、发送DHCP或与真实网络交互。
独立持久入口：.venv/bin/ipv4-admin --db run/pool.sqlite init --cidr 192.0.2.0/30（先mkdir -p run）；随后acquire --now 0 --client A --ttl 10、list --now 10、release --now 10 --client A。数据库父目录须存在。init同CIDR幂等，异CIDR拒绝。
now为0..10^12逻辑整数tick，每次操作不得倒退；ttl=1..10^9，expires<=now先回收。acquire同活跃client续租原地址、expires重置为now+ttl；新client取最小空闲地址，release无记录正常。BEGIN IMMEDIATE、client主键及address唯一约束，耗尽/时钟错误整事务回滚，连过期清理和clock都不提交。list也会提交过期清理与clock。
JSON入口是隔离临时数据库中的可重现操作演示，输入cidr及operations，输出每次事务后的状态；实际跨命令持久化用ipv4-admin。样例A=.1到10、B=.2到20，10时C复用.1到15，20时空池。只保留当前租约及按需启用的归属历史（见下节），无请求回执/高可用/恶意文件并发替换沙箱；本地可信单数据库，SQLite协调连接并发。

## 一次性期望集合对账

`ipv4-admin --db DB reconcile --source FILE` 在池内重新安排整批租约；`Pool.reconcile(now, demands, blocked)` 为对应API。它不访问网络，`init/acquire/release/list` 与JSON演示入口的既有契约不变。

输入文件严格为 `{"now":整数,"demands":[{"client":标识,"ttl":整数,"allowed":[严格IPv4 CIDR,...]},...],"blocked":[严格IPv4 CIDR,...]}`，沿用8MB严格JSON读取与now/ttl/标识校验。最多128个互异client；每项`allowed`为1..32个CIDR；`blocked`至多128个。重复client、未定义字段、布尔整数、IPv6、host bits一律拒绝。CIDR可为/0../32，成员含其全部地址；实际候选还必须属于池的可用hosts、该client的allowed并集，且不在blocked并集内。

`demands` 是事务完成后全部活跃client的权威集合：未列出的原活跃client被删除，`expires<=now` 者不算原活跃，空`demands`合法并清空池。每个需求恰得一个互异地址，`expires=now+ttl`（按各自ttl重置）。原活跃指事务开始所读状态中`expires>now`；迁移只统计其中仍在`demands`且地址改变的client，新建、过期与被删除client都不计。

目标是两级全局最优：先最小化迁移client数；在该最优值内，把client按Python字符串排序后，用各自IPv4数值组成的地址向量取字典序最小。实现把两级目标编码为单一整数代价，用最小代价完美匹配（连续最短增广路）求解；每个client只保留其最小的n个可行地址及其原地址（n为需求数），已足以包含两级最优解，不枚举完整分配，也不依赖demands/CIDR的排列、重复或交叠。

对账在单次 `BEGIN IMMEDIATE` 中读取原租约与clock、拒绝now倒退、计算并写入全部新租约与clock。无完整分配或任何校验/写入错误时租约、过期清理和clock全部回滚；成功时可合法交换两个活跃client的地址而不触发address UNIQUE冲突。它与旧操作按同一SQLite串行顺序生效。

成功返回原有`cidr`、`clock`、按地址数值排序的`leases`，并额外返回按client排序的`moved_clients`。CLI成功输出该JSON并退出0；非法或不可行时退出2并向stderr说明原因，不输出成功JSON，数据库保持不变。

## 历史与离线流量归属

启用历史后，每次成功的`acquire/release/list/reconcile`都在原租约事务内追加一条历史事件（连续`seq`和该操作的`now`）；即使状态没有变化也追加。失败操作不留历史、不消耗`seq`。历史保存每次提交后的完整租约状态（按地址差量），因此可以重建任意时刻的持有关系。

`Pool.enable_history()` / `ipv4-admin --db DB history-enable` 成功返回`cidr`、`coverage_start`、`clock`、`snapshot_seq`。新建池在`initialize`时即从`clock=0`建立覆盖起点和`seq=0`的空基准。旧库没有历史时旧操作照常可用，但必须显式启用：启用会原子保存当时的`clock`为`coverage_start`，并把当时租约记为`seq=0`基准，不倒推更早事实。重复启用（包括多连接并发）或重复`init`不改起点和序号；启用不推进`clock`、不清理也不更改租约。未启用时`attribute`报错，且不会借查询迁移schema。

查询`Pool.attribute_flows(flows)` / `ipv4-admin --db DB attribute --source FILE --output FILE`在一个SQLite只读一致事务中读取`coverage_start`、`clock`、最新`seq`及所需历史；不更新clock、租约或历史。旧`list`不参与只读查询，当前`leases`也不能推断过去。

输入文件严格为`{"flows":[{"id":标识,"address":IPv4字符串,"start":整数,"end":整数,"bytes":整数},...]}`，最多10000条，`id`互异，`start/end`为`0..10^12`且`start<end<=`所读`clock`，`bytes`为`0..10^18`；沿用8MB严格JSON与标识校验，拒绝未知字段、重复键、布尔整数、非IPv4和非法时段。

时间归属采用半开区间。同一tick多个成功操作时，该tick起使用`seq`最大的最终状态；后一次操作覆盖前一次对未来的预期，但不会改写此前时间。两操作时刻之间按最近已提交状态的`expires`判断持有者，`expires`恰到即空闲。`release`立即终止；`reconcile`可交换地址或整集删除；续租可缩短或延长。相同持有者跨操作边界连续时合并为最大连续段，零时长状态不产生段。

每个flow按时间输出不重叠且完整覆盖`[start,end)`的最大连续`segments`，字段为`start/end/status/client/bytes`。`status`为`owned`、`free`、`unknown`或`outside_pool`：池可用hosts内且早于`coverage_start`为`unknown`；覆盖内无持有者为`free`；有持有者为`owned`并填`client`；其他`client`为`null`；非池可用hosts地址全程`outside_pool`（优先于`unknown`，沿用/31与/32的hosts语义）。

先形成最大连续归属段，再按段长度占flow总时长比例分配整数字节：先各取精确有理份额的下整，余字节按小数余数从大到小、同余数按`start`从小到大各加1；全程整数运算，精确守恒。报告`flows`按`id`排序、`segments`按`start`排序、`totals`按`(status, client或空串)`排序并逐组汇总已分摊bytes。API返回`cidr`、`coverage_start`、`clock`、`snapshot_seq`、`flows`及`totals`；CLI另加`source_sha256`（源文件原字节摘要），stdout输出同一完整报告、退出0，并原子发布到`--output`。出错退出2并保留旧报告；拒绝source/output/database路径冲突及符号链接输出。
