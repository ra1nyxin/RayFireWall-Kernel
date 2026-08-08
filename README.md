# RayFireWall-Kernel

RayFireWall 是面向常见 Linux 发行版的内核态包过滤防火墙。数据面运行于
Netfilter，用户态通过 Generic Netlink 与内核通信，不依赖 libnl、Python 或图形界面。
CLI 的帮助、状态、错误和操作结果均为中文，同时保留稳定的英文命令，方便脚本调用。

## 功能

- IPv4 与 IPv6 的 INPUT、OUTPUT、FORWARD 链
- TCP、UDP、ICMP、ICMPv6 与任意协议匹配
- 源/目标 CIDR、源/目标端口范围、入/出接口匹配
- NEW、ESTABLISHED、RELATED、INVALID、UNTRACKED 连接状态匹配
- ACCEPT、DROP 动作，规则优先级及每条规则的包/字节计数
- 限速内核日志，避免日志型拒绝服务
- 每条日志含源/目标地址、端口、接口和命中规则，便于关联事件
- 每个网络命名空间独立的规则、策略和启停状态
- 原子规则集事务：配置恢复失败不会暴露半成品策略
- Generic Netlink 管理接口权限检查（修改需要 `CAP_NET_ADMIN`）
- 中文 CLI、JSON 查询输出、文本持久化、离线配置检查
- DKMS 自动重编、systemd 开机恢复和 Bash 补全

## 支持范围

目标系统包括 Debian、Ubuntu、Kali Linux、Fedora、Arch Linux 与 Amazon Linux，内核
版本建议为 5.15 或更高。构建需要与当前运行内核完全匹配的头文件。Secure Boot 开启时，
自编译模块需要按发行版流程签名，否则内核会拒绝加载。

`scripts/install.sh` 会自动识别 APT、DNF/YUM 与 Pacman，并安装编译器、`kmod` 与当前
运行内核对应的头文件；用户无需预先手动安装依赖。Debian 系会安装并优先使用 DKMS；
其他发行版若未提供 DKMS，则安全回退为安装当前内核模块。手动执行 `make` 时，系统仍
需要具备编译器和匹配的内核头文件。

## 构建

```bash
make
./cli/rayfwctl --version
```

只编译指定内核：

```bash
make KDIR=/lib/modules/6.8.0-xx-generic/build
```

普通安装会优先使用 DKMS；不会创建远程 Git 仓库：

```bash
sudo ./scripts/install.sh
sudo rayfwctl status
```

卸载会保留 `/etc/rayfw/rules.conf`：

```bash
sudo ./scripts/uninstall.sh
```

## 新 Debian 云 VPS 上线手册

以下流程假定 VPS 使用 SSH 的 22 端口。若实际端口不同，先把
`/etc/rayfw/rules.conf` 中的 `--dport 22` 改为实际端口；不要在确认 SSH 放行规则
之前设置 INPUT 默认拒绝。全程保留一个已登录的 SSH 会话，并同时打开云厂商 Web/VNC
控制台。控制台是网络策略配置失误时的最后恢复手段。

进入源码目录并执行安装脚本即可。脚本会自动安装构建依赖和当前内核头文件：

```bash
cd /path/to/RayFireWall-Kernel
sudo ./scripts/install.sh
```

安装脚本会写入一份安全的基础配置到 `/etc/rayfw/rules.conf`。它默认允许回环接口、
已建立和关联的连接、IPv4 ICMP、IPv6 ICMPv6，以及 TCP 22；INPUT 和 FORWARD 默认
拒绝，OUTPUT 默认允许。先检查，再恢复该配置：

```bash
sudo rayfwctl check /etc/rayfw/rules.conf
sudo rayfwctl load /etc/rayfw/rules.conf
sudo rayfwctl status
sudo rayfwctl list
```

在第二个终端重新建立一次 SSH 连接，确认新会话可用后，再关闭最初保留的会话。确认
systemd 已启用，以便模块加载后自动恢复同一份配置：

```bash
sudo systemctl enable --now rayfw.service
sudo systemctl status rayfw.service
```

只开放实际使用的服务。例如该 VPS 同时提供 HTTPS 和 UDP WireGuard，可在 SSH 规则
之后加入：

```bash
sudo rayfwctl add --chain input --action accept --proto tcp --dport 443 --priority 110
sudo rayfwctl add --chain input --action accept --proto udp --dport 51820 --priority 120
sudo rayfwctl save
```

`save` 使用原子重命名写入配置。每次变更后均先执行 `check`，再用 `list` 检查规则
ID、优先级和命中计数。规则数字越小越先匹配。

```bash
sudo rayfwctl check /etc/rayfw/rules.conf
sudo rayfwctl list
sudo rayfwctl --json status
```

若误配置而导致连通性异常，使用云控制台执行以下命令立即旁路 RayFireWall；已有规则
会被保留，修正后可再次 `enable`：

```bash
sudo rayfwctl disable
sudo rayfwctl list
```

在同时使用 nftables、iptables、UFW 或云厂商主机防火墙时，必须先统一规则设计。它们
可能在同一 Netfilter 钩子上共同判决，不能假定某一方一定先执行。云厂商安全组仍应保留
最小化的 SSH 放行规则，不要只依赖主机内的防火墙。

## 遭遇攻击时的实战操作

以下是三个不同来源的攻击响应例子。规则只对当前网络命名空间生效，普通云 VPS 一般
使用初始网络命名空间。先在日志和服务日志中确认来源地址，避免因为伪造或转发地址而
误封正常用户。带 `--log` 的规则会限速写入内核日志，可通过 `rayfwctl logs -f` 实时
观察；规则的包/字节计数则用于确认阻断是否命中。

### 66.66.66.66：SSH 口令爆破

假设认证日志持续出现来自 `66.66.66.66` 的 SSH 失败登录。优先级设为 1，使其先于
“已建立连接”和“允许 SSH”的规则判决，从而立即断开该来源对 SSH 端口的访问：

```bash
sudo rayfwctl add --chain input --action drop --src 66.66.66.66/32 \
  --proto tcp --dport 22 --log --priority 1
sudo rayfwctl list
sudo rayfwctl logs -f
```

确认计数增长后保存：

```bash
sudo rayfwctl save
```

该规则是人工、针对单一 IP 的即时响应，不能替代 Fail2ban、SSH 密钥登录、关闭密码
认证和云厂商的爆破检测。攻击者更换源地址时，应从认证日志重新确认来源；不要把没有
证据的整个网段直接加入黑名单。

### 66.66.66.67：Web 端口扫描和 HTTP 应用探测

假设 Web 访问日志显示 `66.66.66.67` 持续枚举路径、扫描 80/443 或尝试漏洞载荷。
RayFireWall 工作在三、四层，无法识别 URL、HTTP Header 或 SQL 注入内容；因此面对
已经确认的恶意来源，应直接阻断该来源的全部入站协议，并同时在 Nginx、Apache 或应用
日志中保留证据：

```bash
sudo rayfwctl add --chain input --action drop --src 66.66.66.67/32 \
  --log --priority 2
sudo rayfwctl list
sudo rayfwctl logs -f
sudo rayfwctl save
```

若业务必须防护未知来源的 HTTP 攻击，需要额外部署 WAF、应用鉴权、速率限制、及时
更新依赖和审计 Web 日志；这些不是包过滤防火墙能替代的能力。

### 66.66.67.77：ICMP/UDP 侦察或针对转发流量的攻击

假设该地址先进行 ICMP 探测或 UDP 扫描。仅想阻断这两种协议时，可分别添加精确规则：

```bash
sudo rayfwctl add --chain input --action drop --src 66.66.67.77/32 \
  --family ipv4 --proto icmp --log --priority 3
sudo rayfwctl add --chain input --action drop --src 66.66.67.77/32 \
  --family ipv4 --proto udp --log --priority 4
```

若 VPS 承担路由、容器出口或端口转发，攻击流量可能经过 FORWARD 链而非 INPUT 链。
默认配置已经将 FORWARD 设为 DROP；若未来必须开启转发，应为该来源额外设置明确的
转发拒绝规则：

```bash
sudo rayfwctl add --chain forward --action drop --src 66.66.67.77/32 \
  --family ipv4 --log --priority 1
sudo rayfwctl save
```

如果该地址继续攻击其他协议，或已经确认它没有正常业务用途，可以用一条不带协议条件
的 INPUT 规则阻断它的全部入站流量：

```bash
sudo rayfwctl add --chain input --action drop --src 66.66.67.77/32 --log --priority 1
sudo rayfwctl save
```

单台 VPS 的本地防火墙只能在数据包到达网卡后丢弃它，无法消除上游带宽耗尽。遇到大
流量 DDoS 时，应立刻在云厂商安全组、清洗服务或上游网络层封禁，并保留时间、源地址、
端口、协议和流量证据以便提交工单。

### 日常黑名单维护与撤销

先用列表找到规则 ID，再删除一条不再需要的封禁规则并保存。不要使用 `flush` 清空
生产主机规则，除非已经通过控制台确认恢复方案。

```bash
sudo rayfwctl list
sudo rayfwctl delete <规则ID>
sudo rayfwctl save
```

IPv4 和 IPv6 是独立地址族。上述三个地址均为 IPv4；若攻击来自 IPv6，使用 IPv6 CIDR
并显式指定 `--family ipv6`，例如：

```bash
sudo rayfwctl add --chain input --action drop --family ipv6 \
  --src 2001:db8:bad::1/128 --log --priority 1
sudo rayfwctl save
```

## 更多常用操作

```bash
# 丢弃并记录某个 IPv4 网段
sudo rayfwctl add --chain input --action drop --src 203.0.113.0/24 --log --priority 50

# 允许 IPv6 ICMP，避免破坏邻居发现和路径 MTU
sudo rayfwctl add --chain input --action accept --family ipv6 --proto icmpv6 --priority 30

# 输出机器可读结果
rayfwctl --json status
rayfwctl --json list

# 修改前离线检查配置
rayfwctl check /etc/rayfw/rules.conf

# 查看带 --log 规则产生的日志
sudo rayfwctl logs -f
```

命令完整说明见 `rayfwctl help` 或 `man rayfwctl`。

## 配置恢复安全性

`rayfwctl load` 会在事务暂存集内先停用过滤，把三个默认策略临时设为 ACCEPT，再清空旧
规则并逐行加载。只有配置文件所有行均成功应用后，文件末尾的 `enable` 才会重新启用
过滤。发生
语法或内核错误时，活动规则集不会被修改；内核会丢弃暂存规则集，防止半份配置导致主机
失联或短暂放行。

保存采用同目录临时文件、`fsync` 和原子重命名，默认文件权限为 0600。规则文件不执行
Shell，只接受 `policy`、`add`、`enable`、`disable` 四种固定语句。

## 设计

数据包进入 Netfilter 钩子后，以 RCU 方式读取按优先级排列的规则；规则命中计数使用
原子变量，数据包路径不获取管理互斥锁。单条变更采用 copy-on-write 发布；配置恢复会
在独立暂存规则集上执行，并通过一次 RCU 指针替换提交。添加、删除、清空和策略变更
通过 Generic Netlink 完成。内核会再次校验所有用户态字段，因此 CLI 不是安全边界。

规则 ID 在当前网络命名空间和本次模块生命周期内唯一。相同优先级按添加顺序匹配，
数字较小的优先级先匹配。非首片 IP 分片没有传输层端口，因而不会命中带端口条件的规则。
首片分片仍会解析其传输层头。默认每个网络命名空间最多允许 1024 条规则，可在加载模块
时通过 `max_rules_per_net=<数量>` 调整；此上限用于限制线性规则匹配带来的 CPU 与内存
消耗。配置恢复事务默认 30 秒超时自动中止，可通过
`transaction_timeout_ms=<毫秒>` 调整；超时不会改变活动规则集。

## 开发验证

```bash
make clean all
make test
modinfo kernel/rayfw.ko
```

加载模块和更改规则会影响本机网络，仓库测试默认只做编译与离线 CLI 检查。需要在隔离
虚拟机中进行动态测试时，可手动执行 `sudo insmod kernel/rayfw.ko`，测试结束后执行
`sudo rmmod rayfw`。

本项目使用 GPL-2.0 许可证。
