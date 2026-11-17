# Exclusive IPv4 lease pool v1
本地地址管理员维护一个SQLite数据库对应一个严格CIDR IPv4 /20../32地址池。/20../30排除network/broadcast；/31两地址可用、/32单地址可用，采用Python ipaddress hosts语义。最多4094普通主机。不会配置网卡、发送DHCP或与真实网络交互。
独立持久入口：.venv/bin/ipv4-admin --db run/pool.sqlite init --cidr 192.0.2.0/30（先mkdir -p run）；随后acquire --now 0 --client A --ttl 10、list --now 10、release --now 10 --client A。数据库父目录须存在。init同CIDR幂等，异CIDR拒绝。
now为0..10^12逻辑整数tick，每次操作不得倒退；ttl=1..10^9，expires<=now先回收。acquire同活跃client续租原地址、expires重置为now+ttl；新client取最小空闲地址，release无记录正常。BEGIN IMMEDIATE、client主键及address唯一约束，耗尽/时钟错误整事务回滚，连过期清理和clock都不提交。list也会提交过期清理与clock。
JSON入口是隔离临时数据库中的可重现操作演示，输入cidr及operations，输出每次事务后的状态；实际跨命令持久化用ipv4-admin。样例A=.1到10、B=.2到20，10时C复用.1到15，20时空池。只保留当前租约，无审计历史/请求回执/高可用/恶意文件并发替换沙箱；本地可信单数据库，SQLite协调连接并发。
