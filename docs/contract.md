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

## 离线有序ACL首命中差异审计（acl-diff）

`Pool.acl_diff(before, after)` / `ipv4-admin --db DB acl-diff --source FILE --output FILE`在单个SQLite只读一致快照中只读取`cidr`与`clock`，对两版有序ACL策略做精确的首命中（first-hit）差异审计；全程离线、不访问真实网络，不推进clock、不清理到期租约或外部事实、不写入任何表，也不读取租约、外部占用或归属历史（无历史表的旧池同样可审计，且不调用旧list查询）。沿用/31、/32的hosts语义，源分析域始终只是本池的全部可用hosts，与当前租约、外部占用和归属历史无关。

**分析域**：本池全部可用源hosts × 全部2^32个目标IPv4地址 × `{tcp,udp}` × 目标端口0..65535，无源端口维度；目标域不剔除任何network或broadcast地址。`total_packets = 可用源hosts数 × 2^32 × 2 × 65536`，是精确整数，不以租约数、规则数或地址段数代替。

**输入**：文件顶层严格为`{"before":[...],"after":[...]}`（API直接接收两个数组；空策略数组合法，表示整域默认拒绝）。沿用8,000,000字节严格JSON读取（重复键、非有限数值拒绝）。每版至多64条规则，数组顺序即业务优先级，绝不按id、前缀长短或action重排；deny与allow都参与第一命中。每项严格为`{id,src,dst,protocol,ports,action}`，所有字段必填且拒绝额外字段：`id`沿用ident校验、各版内互异，两版允许相同id；`src`/`dst`必须是严格IPv4 `/0../32` CIDR字符串，拒绝IPv6、host bits及非字符串，规则前缀允许覆盖池外、允许/0，**不**套用池CIDR的/20下限；`protocol`为`tcp`、`udp`或`any`（`any`同时覆盖tcp与udp，端口区间对两者意义相同）；`ports`必须是恰有两个整数的闭区间`[lo,hi]`且`0<=lo<=hi<=65535`，布尔值不算整数；`action`为`allow`或`deny`。CIDR匹配包含其全部地址，但源分析域始终限于本池可用hosts（规则源范围与池hosts求交，完全在池外的规则保留位置且零覆盖）。

**首命中语义与区域表示**：按数组顺序取全部条件同时成立的第一条规则，无命中默认deny且规则id为null。实现以不相交的**盒子（box）**列表表示区域，盒子为`(src闭区间, dst闭区间, 协议2位掩码, 端口闭区间)`，计数全部是区间宽度的精确整数乘积，绝不逐目标地址、逐端口或逐数据包枚举。三项正确性义务由结构保证：

1. *首命中遮蔽*：逐条规则按输入顺序处理，规则的有效（effective）区域=原始（raw）匹配盒子减去此前所有规则有效区域的并；盒子相减只在操作数边界切割并产出互不相交的分区，更早覆盖的包域被精确扣除，绝不重复计数。无任何规则命中的包落入默认deny区域（整域减去全部有效区域）。
2. *精确交集*：每版的有效区域加默认区域是一组互斥盒子且恰好覆盖整域一次；两版分区两两求交得到的转移区域同样互斥且恰好覆盖整域一次，因此转移计数之和严格等于`total_packets`，而不是比较两版allow总量。
3. *最大端点与最小见证*：相减只在边界切割、保留最大端点，每个盒子的下角即该盒内真实存在的包；按`(src数值, dst数值, tcp先于udp, port)`的字典序，盒内最小包就是其下角，取区域内各盒最小者即得该组合的最小witness，不做任何抽样。

**逐规则用量**：`before`/`after`按该版输入规则顺序列出全部规则（零覆盖也保留），最后各附一条默认项；每项严格为`{id,action,raw_packets,effective_packets,shadowed_packets}`。普通项`action`为原规则action，`raw_packets`为域内原始匹配数、`effective_packets`为实际首命中数、`shadowed_packets=raw-effective`；默认项`id=null`、`action=deny`、`raw_packets=total_packets`、`effective_packets`为该版全部未命中包数、`shadowed_packets=total-effective`。单版所有`effective_packets`（含默认项）之和等于`total_packets`。

**转移与放行变化**：`transitions`每项严格为`{before_rule,after_rule,before_action,after_action,packets,witness}`，规则字段为id或默认null，action从对应规则或默认项确定；只输出`packets>0`的组合，每个组合只出现一次，按`before_rule`再`after_rule`排序，各维按Python字符串顺序、null排在全部字符串之后。同action但首命中id改变、乃至id与action完全相同的组合都保留。对`before_rule`或`after_rule`分别做边缘汇总，恰等于对应版的`effective_packets`。由这些组合汇总deny→allow的`newly_allowed`与allow→deny的`newly_denied`。`witness`为`{src,dst,protocol,port}`，src/dst为规范IPv4字符串、protocol只能为tcp或udp、port为整数，必须真实属于该组合并满足题述最小包序。全部数值用整数精确计算与JSON序列化，无浮点近似。

**事务与CLI**：分析在单个只读快照读取cidr/clock，输入不合法、池未初始化、计算或发布失败都不改变业务数据库。CLI在API相同报告上增加`source_sha256`（输入原字节SHA256），以现有原子发布方式保存完整JSON并在stdout输出相同报告，成功退出0；错误退出2且仅向stderr说明原因，不打印成功JSON并保留已有输出。输入、输出、数据库须为不同路径，三者的符号链接均拒绝；缺失数据库失败且不创建空库。

## 持久离线DNS数据镜像（dns-config / dns-snapshot）

`Pool.configure_dns(now, zone, bindings, aliases)` / `ipv4-admin --db DB dns-config --source FILE` 安装或整份替换一份持久的离线DNS配置，`Pool.dns_snapshot()` / `ipv4-admin --db DB dns-snapshot --output FILE` 在只读一致快照中编译结构化镜像。仅用Python标准库与SQLite，不访问任何DNS服务、不监听端口、不产生wire格式/zone文件/SOA/NS/DNSSEC；镜像是供下游消费的记录集合。

**派生而非物化**：DNS表只持久化配置（zone、bindings、aliases），记录本身始终在每次需要时由“所用now的最终活跃租约 + 本次生效配置”即时派生，因此不存在会过期的物化记录行。所有写入口（`acquire/release/list/reconcile/import_dhcp`及再次`dns-config`）都在各自原`BEGIN IMMEDIATE`事务内、对最终状态调用与快照**同一个**编译器做完整性校验，校验不过则整个事务回滚；快照只读取并编译，不清理、不写表、不推进clock。

**名称校验与规范化**：zone及bindings/aliases中的名称必须是完整ASCII hostname，可有可无一个末尾点；规范化为小写并恰有一个末尾点。去掉可选末尾点后总长1..253字节，每label为1..63字节的ASCII字母、数字或连字符，首尾必须是字母或数字；拒绝Unicode/IDNA形式的非ASCII名称、下划线、空label、非法连字符、前后空白、连续或多个末尾点、长度越界。bindings的`name`、alias的`name`及`target`必须等于zone本身或按完整label边界（`.zone.`）结尾于zone，字符串后缀伪装的区外名称（如zone为`lab.test`时的`notlab.test`）拒绝。client身份沿用ident精确字符串相等，不做DNS名称或大小写转换。`reverse`只接受真实bool。

**配置文件与API入参**：文件顶层严格为`{"now":整数,"zone":名称,"bindings":[{"client":标识,"name":名称,"reverse":布尔值},...],"aliases":[{"name":名称,"target":名称},...]}`，四字段必填、拒绝额外字段，沿用8,000,000字节严格JSON（重复键、非有限数、错类型拒绝）；API四参对应顶层四值，aliases中的`name`即CNAME owner。`now`为0..10^12非布尔整数；bindings至多128项且client互异（即使binding完全相同，重复client也拒绝），aliases至多2048项且规范化后owner互异（无论target是否相同）；两数组均允许为空。alias owner不得等于zone顶点。bindings可引用尚无租约的休眠client，同一name可绑定多个不同client；不要求每个已有client都有binding，未绑定client不贡献任何记录。

**记录语义（活跃仅按最终租约`expires>所用now`判断）**：
- *A*：每个被binding引用且有活跃租约的名称生成一个多值A RRset，values为全部贡献租约地址的规范IPv4字符串并按地址数值排序；TTL取所有贡献租约`expires-now`的最小值。同一client只绑定一个name。
- *PTR*：`reverse=true`的活跃租约，每个贡献地址生成一个PTR RRset，owner为四个IPv4十进制字节逆序加`.in-addr.arpa.`（如192.0.2.1→`1.2.0.192.in-addr.arpa.`），values为单个规范绑定名称，TTL为该地址自身的`expires-now`（不取同名A的最短TTL）；`reverse=false`与CNAME均不产生PTR。
- *CNAME*：aliases是区内有向关系，owner唯一、每项一个直接target（values只含直接target，不展开为终端名或IP）。每条链必须无环且终止于非空A RRset；CNAME owner不得同时具有活跃A（休眠binding可与CNAME同名，但其client一旦取得地址即重新检查冲突）。多层别名每层TTL均取最终非空A RRset的TTL，因此缩短/延长租约会沿整条依赖链同步改变TTL。环（含自环）与悬空链确定性拒绝；链遍历为带显式visited集合的迭代算法，支持1500层链/2048个别名而不依赖Python递归深度。
- 外部DHCP宣告不是本地client，不直接生成任何DNS记录；它对旧分配的限制保持原义。

**事务与原子性**：`dns-config`是整份配置的权威替换（zone、bindings、aliases一起替换，不保留已删除部分；空bindings加空aliases是合法配置）。它在同一`BEGIN IMMEDIATE`事务内拒绝时间倒退、清理到期本地/外部事实、首次建立DNS配置存储（之后整份替换）、编译最终镜像、推进clock，并在已启用归属历史时于同一事务追加一条原post-state历史事件（不替旧池启用历史，不重复调用旧list推进时间；相同配置重复成功也恰追加一次历史）。任何冲突、悬空链、环或SQL失败都回滚租约、外部事实、clock、历史seq与DNS配置，不能先提交租约再修DNS。原`acquire`（新地址与续租）、`reconcile`（权威集合及两级全局目标）、`import_dhcp`（外部占用身份）的算法与返回JSON字段保持原样，DNS守卫只对它们原本可成功的最终结果作完整性判断，不绕开原分配目标另找DNS可行解，也不额外附加DNS字段。

**启用边界与旧库兼容**：仅`dns-config`可首次建立DNS配置存储；未配置的旧库/新库上，旧入口的行为、结果、外部事实与历史契约保持原样，旧写入口不得仅因升级而创建DNS表。只有确实不存在DNS配置表/配置行时才视为未启用；损坏表或其他SQL错误必须传播。`dns-snapshot`在未配置时明确失败且不偷偷建立配置。无归属历史的旧池可以配置DNS但仍无历史；重复`init`与`history-enable`不改DNS配置、不重写镜像或clock。

**快照一致性**：`dns_snapshot`在单个只读事务内读取cidr、clock、zone、配置与活跃租约，因此clock、zone与records必来自同一提交；两个连接的配置更换与租约操作由SQLite按单一提交顺序串行生效，快照只能读到完整提交，读不到半份配置或已失效的旧记录。只读方法不调用会清理的旧list，也不在查询中迁移表；快照计算/发布失败保留已有报告且业务数据库不变（不要求跨SQLite与输出文件的断电原子性）。

**返回与CLI**：`configure_dns`与`dns_snapshot`成功返回结构严格相同：`{cidr,clock,zone,records}`；`records`每项严格为`{name,type,ttl,values}`，type为`A`、`CNAME`或`PTR`，ttl为正整数，按`(name,type)`的Python字符串顺序排序，同一`(name,type)`只出现一项，空镜像`records=[]`。API不含`source_sha256`；`dns-config`只在其成功stdout报告上额外增加`source_sha256`（源文件原字节摘要），`dns-snapshot`无输入文件、不加源摘要，并以现有原子发布方式把与API相同的报告保存到`--output`且在stdout打印相同内容。成功退出0；错误退出2、只向stderr说明原因且不输出成功JSON。dns-config源文件与数据库不得同一路径或硬链接至同一文件，dns-snapshot输出与数据库亦然；数据库、源文件、输出本身的符号链接均拒绝；缺失/未初始化数据库失败且不创建空数据库。

