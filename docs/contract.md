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

## 离线DHCP外部占用（import-dhcp）

`Pool.import_dhcp(now, capture_path)` / `ipv4-admin --db DB import-dhcp --now N --source FILE`把PCAP中的有效DHCPACK转成有期限的外部地址占用。仅用Python标准库与SQLite，不访问网络；API读取`capture_path`原字节，CLI只衔接入口。

**容器**：仅经典PCAP v2.4，支持大端（魔数`a1b2c3d4`）与小端（`d4c3b2a1`）的微秒时间格式，linktype必须为Ethernet(1)，不支持pcapng或纳秒魔数（`a1b23c4d`/`4d3cb2a1`）。文件≤8,000,000字节；校验24字节全局头、每个16字节记录头与记录边界，snaplen为1..262144，每帧`0<incl_len=orig_len<=snaplen`，usec为0..999999、秒数为0..now。坏头、截断或不支持的容器使整次失败。时间戳不要求按文件顺序递增；秒数直接作为本池tick单位，微秒仅校验范围，不参与租约TTL。

**帧与IP**：帧至少14字节Ethernet头，仅处理EtherType=0x0800且protocol=17的IPv4帧，其他EtherType/协议忽略；不处理VLAN、IPv6或IP options。受处理帧必须version=4、IHL=5，total_length为20..65535且不超捕获字节，IP头校验和正确，保留flag为0，DF不能与MF或非零offset同现；total_length之外的Ethernet padding忽略。IP分片offset以8字节为单位，载荷必须非空，MF=1时载荷长度须为8的倍数，offset加载荷长度不得超过65515。

**重组**：按`(src,dst,protocol,id)`跨帧重组，支持乱序、交错及字节相同的重复/交叠分片；重叠字节不一致、终片长度矛盾、缺零偏移片、缺MF=0终片或留有空洞均拒绝整个导入，即使此前已拼出完整报文、后续冲突仍使整次失败。约定同一文件的同一四元组仅代表一个IP数据报；终片确定的总载荷长度唯一，任何片的字节都不得超出该长度。每组`observed_at`取所有零偏移片中最早的捕获秒数。全部组都通过后才处理入库；未分片UDP走相同一致性规则。

**UDP/DHCP**：完整UDP载荷至少8字节，UDP length须与重组字节数一致；checksum=0合法，否则用IPv4伪首部（奇数字节补零）验证。只解码67→68端口，其余UDP忽略。DHCP至少240字节且magic cookie为`63825363`；options按pad=0、end=255及长度字节解码，越界或缺end拒绝，end后字节忽略，未知option忽略。option 52（仅可在主options出现一次、值1/2/3）选择file/sname过载区域，所选区域按同一TLV规则解析且其内不得再出现52。option 53须跨所有已选区域恰好出现一次且长度1；非ACK（type≠5）只忽略。ACK须op=2、htype=1、hlen=6，option 51与54各恰一次且长度4；51为网络序1..10^9的TTL，54为非零server IPv4，yiaddr须非零，mac取chaddr前6字节规范为小写冒号。必需option重复、长度错或不合法均使整次失败。yiaddr不属于本池可用hosts的ACK忽略（沿用/20../30及/31、/32的hosts语义）。

**事实与到期**：一条事实以五元组`(server,mac,address,observed_at,ttl)`标识，`expires=observed_at+ttl`（最早零偏移捕获秒数加option 51秒数，不能取导入now加TTL）。仅保留`expires>当前操作now`的事实，到期恰等于now即失效；相同五元组重复导入不累加也不延长，旧捕获到期后重导不得复活；不同server或mac对同地址的独立宣告分别保留，互不覆盖。不得从当前本地leases或既有归属历史伪造外部事实。

**事务**：导入在一次`BEGIN IMMEDIATE`中按原clock拒绝时间倒退，清理到期本地租约与外部事实、写入本次仍有效事实、推进clock，并在已启用历史时于同一事务追加一条原post-state历史事件；任何解析、校验或写入失败都不改变租约、外部事实、clock及历史序号。旧库仅在第一次`import-dhcp`显式建立新表，旧命令不因缺表失效；只有确认外部表不存在时才视为空集合，损坏或其他SQL错误不得吞掉。导入不会替旧库偷偷启用历史；`attribute_flows`保持只读，不清理或写入外部事实，也不把第三方宣告当作本地持有者。

**与本地租约的关系**：有效外部占用不驱逐现存本地租约，但在`conflicts`报告同地址活跃client与全部活跃外部事实；冲突不构成导入失败，也不把本地client与mac自动视作同一主体。`acquire`的活跃client原地址若被有效外部占用，续租必须失败、不得偷换地址；新client取符合排除条件的最小空闲地址。`reconcile`仍以原权威demands与原两级全局目标求解，只在实际候选（同事务内）排除`expires>now`的外部地址，不可行时连过期清理整体回滚，`moved_clients`原定义不变。排除发生在各自原写事务内，不能只在CLI预查或把外部事实临时拼成一次blocked输入。`release/list`仍按原规则成功并随事务清理外部到期事实；无外部占用时旧分配目标、返回结构、历史归属与JSON演示结果保持兼容。

**返回**：API与CLI成功返回同一JSON：`cidr`、`clock`、`leases`（原结构、按地址排序）、`claims`、`conflicts`、`source_sha256`（捕获文件原字节SHA256，事实身份不依赖路径或摘要）。`claims`列出提交后全部活跃外部事实，每项为`server`、`mac`、`address`、`observed_at`、`ttl`、`expires`，按`(address数值,server数值,mac,observed_at,ttl)`排序。`conflicts`每项为`address`、`client`、`claims`，按address数值排序，内层`claims`沿用同一排序；无冲突为空数组。拒绝source/database同路径及符号链接source或database。成功stdout输出JSON并退出0；错误退出2、stderr说明原因且不输出成功JSON。

## 离线路由故障影响分析（route-impact）

`Pool.route_impact(routes, scenarios)` / `ipv4-admin --db DB route-impact --source FILE --output FILE`在单个SQLite只读一致快照中读取`cidr`与`clock`，完全离线计算各接口故障情景下本池可用hosts的有效转发出口区间；不连接真实网络，不推进clock、不清理到期租约或外部事实、不写入任何表，也不要求归属历史存在（无历史表的旧池同样可分析）。沿用/31、/32的hosts语义，只分析池的可用hosts。

**输入**：文件顶层严格为`{"routes":[...],"scenarios":[...]}`（API直接接收两个数组），沿用8,000,000字节上限、严格JSON（重复键、非有限数值、未知字段一律拒绝）。`routes`至多2048项，每项严格为`{id,prefix,metric,via,interface}`：`id`为标识且在routes内互异；`prefix`为严格IPv4 `/0../32` CIDR（拒绝IPv6、host bits，**不**套用池的/20下限，可覆盖全空间或完全在池外）；`metric`为`0..10^9`整数（布尔拒绝）；`via`与`interface`恰有一个非null——`via`为严格IPv4文本地址，`interface`为非空标识。同一prefix与metric可有多个不同id的等价路由。`scenarios`至多32项，每项严格为`{id,down}`，`id`在scenarios内互异（与route id不跨类检查），`down`为互异标识列表、至多2048项且每个接口都必须出现在原路由的`interface`中。空routes、空scenarios、空down均合法。

**选路与递归语义**：对任意IPv4地址，先在包含它的前缀中取最长前缀，再在该前缀内取最小`metric`，保留全部并列路由；无匹配即不可达（空集）。直连路由贡献其`interface`；网关路由贡献对其`via`地址按同一规则继续解析得到的接口集合。整体结果是该集合方程组的**最小不动点**：纯循环为空集；循环连通可达出口时必须传播全部出口，不得遇环否定整个分支，也不得把DFS中途得到的暂时空集缓存为最终结果。网关可在池外，仍须用完整路由事实求解。等价路由只贡献接口集合的并，不按路径或id计权重。最优路由集合不可达时结果即空集——最优metric的via陷入纯环时，不得改用仍存在的次优metric直连路由；这是“先按存在的事实选路、再求递归接口集合”的语义，不能预先删除所有不可达via。

**故障情景**：每个情景独立从原路由集合开始，只撤去`interface`属于`down`的直连路由；不直接删除via路由，也不因其不可达而尝试次优metric。撤去更具体的直连路由后，较短前缀或较大metric的候选必须重新参与最长前缀/metric选择。情景间不得泄漏状态：实现为每个情景从过滤后的事实副本构建全新选路结构与图，循环分量按当次事实重新求解，过期出口不会残留。影响核算比较基准与情景的**最终接口集合**（而非被删路由的prefix或首跳），池外网关的出口变化会传导到池内所有依赖地址，即使这些地址的获选路由id完全未变。

**算法与终止**：选路用按前缀组织的二进制trie做最长前缀匹配，每个前缀节点预算该前缀的最小metric路由集。依赖图从池hosts出发、沿获选via惰性扩展（不枚举池外IPv4空间、不枚举递归路径），节点规模受路由数界定。接口标签在图的强连通分量（SCC）压缩DAG上求解：迭代式Kosaraju（无递归深度问题，支持1500层网关链）按拓扑逆序把每个SCC自身直连接口与所有可达后继SCC的标签取并，恰为最小不动点——纯环SCC无自身标签即空集，带出口的环继承全部可达出口。

**输出**：API报告严格包含`cidr`、`clock`、`baseline`、`scenarios`。`baseline`覆盖全部可用hosts的最大连续闭区间，每项为`{start,end,interfaces}`；情景`changes`只列接口集合发生变化的最大连续闭区间，每项为`{start,end,before,after}`，区间按IPv4数值排序、不因路由id或前缀边界人为拆分等价区间，接口集合按Python字符串顺序排序，空数组表示不可达。每情景给出`changed_hosts`（集合改变）、`lost_hosts`（原非空后为空）、`recovered_hosts`（原为空后非空），均按区间内地址数累计而非路由或区间条数；`scenarios`按id排序。CLI在同一报告上增加`source_sha256`，原子保存完整JSON并在stdout打印相同内容，成功退出0。出错退出2并只向stderr说明原因，保留已有报告且不输出成功JSON；拒绝输入/输出/数据库指向同一路径，拒绝三者的符号链接；缺失或未初始化的池失败且不创建数据库。由于故障只撤路由、不增路由，基准为空的地址在任何情景下都不会变为非空，`recovered_hosts`在该语义下恒为0但计数分支仍按通用集合变化实现。
