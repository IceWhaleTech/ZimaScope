# ZimaScope 产品需求文档

| 项目 | 内容 |
|---|---|
| 产品名称 | ZimaScope |
| 产品标语 | See where your ZimaOS traffic flows. |
| 文档版本 | 0.1 |
| 文档状态 | 立项草案 |
| 目标产品 | ZimaOS |
| 产品形态 | ZimaOS 内置网络可观测服务与 Web UI |
| 默认原则 | 本地优先、只采集元数据、轻量、可关闭 |

## 1. 产品概述

ZimaScope 是面向 ZimaOS 用户的轻量网络可观测能力，用于回答以下问题：

- ZimaOS 当前有多少入站和出站流量？
- 哪些 IP、端口、国家/地区、ASN 或云厂商占用了流量？
- 哪些域名与这些连接相关？域名信息来自哪里、是否可信？
- 哪些连接成功、失败、被重置或表现异常？
- 在能够识别时，是哪个 ZimaOS 应用、容器或进程产生了流量？

ZimaScope 不定位为 Wireshark 替代品，也不默认保存完整数据包或业务内容。产品重点是将内核观察到的网络元数据聚合成普通用户能够理解、管理员能够排障的视图。

## 2. 背景与问题

NAS 用户通常运行下载工具、媒体服务、同步服务、远程访问、容器和第三方应用。当出现带宽占满、访问缓慢、异常外联或隐私疑虑时，现有系统监控往往只能展示网卡总流量，无法解释流量的来源和目的。

典型问题包括：

- 用户发现上行带宽持续占用，但不知道流量发往哪里。
- 某个容器无法访问外部服务，不确定 DNS、建连还是对端存在问题。
- 用户希望确认 NAS 是否连接到陌生国家、运营商或云平台。
- 用户需要知道主要访问域名，但 HTTPS、DoH、DoT、ECH 等机制限制了可见性。
- 多个物理网卡、网桥、Docker 网络和 VPN 可能导致重复统计或方向歧义。

## 3. 产品定位

### 3.1 目标用户

**家庭用户**：希望直观看到 NAS 当前在上传、下载什么，以及目标大致位于哪里。

**高级玩家**：运行多个 Docker 应用，需要按 IP、域名、端口和应用排查网络行为。

**小型团队管理员**：需要本地审计异常外联、带宽热点和连接失败，不希望将网络元数据上传云端。

**ZimaOS 支持团队**：在用户授权导出后，利用标准化诊断报告定位网络问题。

### 3.2 核心价值

1. **看得见**：从总带宽下钻到 Flow、Endpoint、Associated Domain 和 IP Profile。
2. **说得清**：展示域名证据和观察盲区，不将推测包装成事实。
3. **用得起**：在 ZimaOS 支持的最低硬件上保持可控的 CPU、内存和磁盘占用。
4. **守隐私**：默认本地处理，不保存报文正文，不向云端上传网络活动。

## 4. 产品目标与非目标

### 4.1 V1 目标

- 提供设备边界上的实时入站、出站 bytes/packets 和速率。
- 提供 IPv4 TCP/UDP Flow 的源/目标地址、端口、方向、持续时间和流量。
- 为公网 IP 提供国家/地区、ASN 和组织信息。
- 通过 DNS、TLS SNI 和明文 HTTP Host 尽可能关联域名。
- 清楚展示域名来源、关联可信度和不可见原因。
- 提供概览、Flow 列表、Endpoint/Domain 详情、过滤、搜索和本地导出。
- 提供数据保留、功能开关、资源上限和服务健康状态。
- 作为 ZimaOS 本地服务安装、升级、停止和卸载。

### 4.2 V1 非目标

- 不保存完整数据包或 HTTP 请求/响应正文。
- 不解密 TLS，不实施中间人代理。
- 不承诺识别 DoH、DoT、ECH 或所有 QUIC/HTTP3 域名。
- 不提供防火墙阻断、流量整形或家长控制。
- 不提供跨多台 ZimaOS 设备的云端集中管理。
- 不保证城市级 IP 定位准确。
- 不在 V1 强制实现进程、容器或 ZimaOS 应用归属。
- 不替代专业 IDS/IPS、NDR 或抓包分析工具。

## 5. 产品原则

- **边界明确**：所有方向均相对 Device Boundary 定义，不使用含糊的上传/下载代替 ingress/egress。
- **聚合优先**：内核侧统计，用户态周期读取，避免逐包永久落盘。
- **证据优先**：Associated Domain 必须附带 Domain Evidence。
- **诚实降级**：不可观察时显示“不可见/仅推断”，不显示虚假域名。
- **本地优先**：GeoIP/ASN 查询、数据库和 UI 均可完全离线运行。
- **默认安全**：不暴露独立公网 API，不默认导出，不采集 payload 内容。
- **控制规模**：V1 只解决网络去向和流量归因，不扩展成通用安全平台。

## 6. 典型用户场景

### 场景 A：定位异常上行

用户看到 NAS 上行达到 80 Mbps，打开 ZimaScope 后看到主要 Outbound Flow 的目标 IP、Associated Domain、ASN、应用端口和流量占比，从而判断是正常备份还是异常外联。

### 场景 B：确认陌生目的地

用户发现一个此前未见的公网 IP。详情页显示其国家、ASN、组织、首次/最后出现时间、相关域名、涉及端口和累计流量，帮助用户决定是否继续调查。

### 场景 C：域名不可见

某条 HTTPS/QUIC Flow 只有 IP，没有域名。UI 明确显示“未观察到 DNS/SNI；可能使用缓存、DoH、ECH 或不携带域名”，而不是将反向 DNS 当作真实请求域名。

### 场景 D：排查连接失败

用户按目标 IP 或域名过滤，查看 TCP 建连失败、RST 或超时趋势。若 V1 无法提供完整 TCP 质量数据，则引导用户导出诊断摘要而不是报文内容。

### 场景 E：多网卡设备

系统自动选择承载默认路由的物理接口作为 Device Boundary。用户可在设置中调整接口，并在可能重复统计 bridge/physical 流量时收到提示。

## 7. 范围与优先级

### 7.1 P0：V1 必须交付

| 编号 | 能力 | 说明 |
|---|---|---|
| P0-01 | 服务生命周期 | 随 ZimaOS 启停；支持启用、暂停、重启和卸载 |
| P0-02 | 边界接口选择 | 自动识别默认路由接口；允许手动选择；规避明显的重复挂载 |
| P0-03 | 双向流量统计 | 分别统计 Inbound/Outbound bytes、packets、当前速率和峰值 |
| P0-04 | Flow 聚合 | IPv4 TCP/UDP 五元组、方向、首次/最后时间、包数和字节数 |
| P0-05 | IP Profile | 地址范围、国家/地区、ASN、组织；内网地址标记为 Local |
| P0-06 | Associated Domain | DNS、TLS SNI、HTTP Host；展示证据、可信度和观察时间 |
| P0-07 | 概览页 | 实时趋势、Top Endpoint、Top Domain、Top ASN/国家、最近 Flow |
| P0-08 | Flow 浏览 | 搜索、过滤、排序、分页、详情和实时刷新 |
| P0-09 | 数据保留 | 默认保留详细记录 7 天；支持 1/7/30 天或关闭历史 |
| P0-10 | 本地导出 | 导出时间范围内的 JSON/CSV 诊断数据；不包含 payload |
| P0-11 | 健康状态 | 展示 attach 状态、map 使用量、丢事件、解析失败和 Observation Gap |
| P0-12 | 隐私控制 | 总开关、域名观察开关、历史记录开关、清除历史数据 |

### 7.2 P1：V1.1 建议交付

- IPv6 TCP/UDP Flow。
- PID、进程名、可执行文件路径和 UID。
- Docker container、Compose project 和 ZimaOS App Identity。
- TCP 建连成功/失败、RST、连接耗时和重传指标。
- 首次出现的 Endpoint、Domain、国家或 ASN 提醒。
- Prometheus/OpenMetrics 本地导出。
- 更细粒度的数据保留和聚合策略。
- 对 VPN、bond、bridge、多默认路由的增强处理。

### 7.3 P2：后续候选

- Kubernetes Pod/namespace 归属。
- QUIC Initial 中的域名识别研究。
- 自定义规则与异常行为检测。
- 用户确认后的阻断或限速能力。
- 多设备集中视图。
- PCAP 按需短时诊断；必须独立授权、限时并明确隐私风险。

## 8. 详细功能需求

### 8.1 服务初始化

1. 安装或系统升级后，ZimaScope 默认可用但允许用户关闭。
2. 首次启用时检测内核、BTF、eBPF、TC 和所需 capability。
3. 自动选择默认路由所在的非虚拟接口作为 Device Boundary。
4. 如果存在多个候选接口，使用安全默认值并提示用户确认。
5. 如果环境不支持 eBPF，UI 必须展示明确原因和建议，不得循环崩溃。
6. 服务升级不能丢失用户设置；数据结构变更必须支持迁移或明确清理策略。

### 8.2 流量采集

1. 分别挂载 TC ingress 和 egress。
2. V1 支持 Ethernet、可选单层 VLAN、IPv4、TCP 和 UDP。
3. 每条 Flow 至少包含：方向、协议、源/目标 IP、源/目标端口、packets、bytes、first_seen、last_seen、interface。
4. Flow key 必须定长且可在 eBPF 与用户态安全共享。
5. 内核侧以 map 聚合；用户态默认每秒读取并生成展示快照。
6. map 达到容量时使用可预测的淘汰策略，并累计 eviction 指标。
7. 无法解析、截断、未知协议和 map 更新失败必须计数，但不得阻断网络流量。
8. 所有 eBPF 路径默认返回放行结果；ZimaScope V1 不改变数据包。

### 8.3 方向与去重

1. Inbound/Outbound 相对 Device Boundary 定义。
2. UI 使用“入站/出站”，可辅以“进入 ZimaOS/离开 ZimaOS”的解释。
3. 默认不同时监控物理 uplink 和其上层 bridge，以降低重复统计风险。
4. 用户手动选择可能重复的接口组合时必须提示。
5. Loopback 默认排除；用户可在高级设置启用。

### 8.4 域名观察与关联

1. 支持从传统 DNS 请求和响应中观察域名、记录类型、响应 IP 和 TTL。
2. 支持从可见的 TLS ClientHello 提取 SNI；不保存完整 ClientHello。
3. 支持从明文 HTTP 请求提取 Host；不保存 URL path、header 集合或正文。
4. 每条 DomainObservation 包含 domain、evidence、observed_at、client context、关联 IP 和过期时间。
5. DNS 关联必须遵守 TTL，并允许设置合理的最短/最长缓存边界。
6. SNI/HTTP Host 直接出现在 Flow 上时标记为 Direct；DNS IP 关联标记为 Inferred。
7. 多域名共享同一 IP 时允许展示多个候选，不强行选定唯一域名。
8. 反向 DNS 只能作为 Endpoint 名称提示，不能标记为请求域名。
9. 域名规范化为小写并去除末尾点，同时保留国际化域名的可显示形式。
10. UI 必须解释以下盲区：DNS 缓存、DoH、DoT、ECH、QUIC、分片、非标准端口和采集启动前已建立连接。

建议的可信度口径：

| Domain Evidence | 可信度 | UI 标签 |
|---|---|---|
| 当前 Flow 的 TLS SNI | 高 | TLS SNI |
| 当前 Flow 的 HTTP Host | 高 | HTTP Host |
| 当前客户端在 TTL 内收到的 DNS 答案 | 中 | DNS 关联 |
| 仅 IP 反向 DNS | 低 | Endpoint 名称，不作为 Associated Domain |
| 无证据 | 无 | 域名不可见 |

### 8.5 IP Profile

1. 仅对公网地址执行地理和 ASN 丰富化。
2. 私网、loopback、link-local、multicast、broadcast 和保留地址必须明确分类。
3. 公网 IP 至少展示国家/地区代码、ASN、组织名称和数据库更新时间。
4. 城市级信息如提供，必须标记为近似信息，不能显示为精确位置。
5. 数据库在本地查询；更新包必须可校验版本和完整性。
6. GeoIP 数据不可用时不影响基础 Flow 采集。
7. UI 允许展示 CDN、云厂商或网络组织，但不得将 ASN 组织等同于域名所有者。

### 8.6 概览页

概览页默认展示最近 15 分钟，可切换 1 小时、24 小时和 7 天。

必须包含：

- 当前 Inbound/Outbound 速率。
- 时间范围内的累计 Inbound/Outbound 流量。
- 流量趋势图。
- Top 10 Endpoint，按总 bytes 排序。
- Top 10 Associated Domain，按总 bytes 排序。
- Top ASN/组织和国家/地区。
- 当前活跃 Flow 数。
- 域名可见率：具有 Direct/Inferred 域名证据的 Flow 占比。
- 采集健康提示和 Observation Gap。

### 8.7 Flow 列表

列表字段：

- 状态：活跃/已结束/过期。
- 方向。
- Application Identity；不可用时显示未知，不隐藏 Flow。
- 源和目标 Endpoint。
- Associated Domain 与 evidence 标签。
- 国家/地区、ASN/组织。
- 协议和端口。
- 发送、接收、总 bytes/packets。
- 首次出现、最后出现、持续时间。

过滤条件：

- 时间范围。
- 入站/出站。
- IP、CIDR、端口和协议。
- Domain。
- 国家/地区、ASN、组织。
- Application Identity。
- 活跃/已结束。
- 有域名/域名不可见。

### 8.8 Endpoint 与 Domain 详情

Endpoint 详情展示：IP Profile、累计流量、首次/最后出现、常用端口、关联域名、相关 Application Identity 和时间趋势。

Domain 详情展示：首次/最后观察、evidence 分布、解析到的 IP、ASN/国家分布、累计流量和相关 Application Identity。

所有详情页必须允许跳回经过过滤的 Flow 列表。

### 8.9 设置与隐私

设置项至少包括：

- 启用/暂停 ZimaScope。
- Device Boundary 接口。
- 域名观察总开关。
- TLS SNI、HTTP Host 观察子开关。
- 历史记录开关与保留时间。
- GeoIP/ASN 数据库状态和更新时间。
- 最大 map 条目、磁盘配额和资源模式；高级设置。
- 导出诊断数据。
- 清除历史数据。

首次打开域名观察说明时，应提示域名属于敏感网络活动元数据，默认仅保存在本机。

### 8.10 导出

1. 支持按时间范围、过滤条件导出 JSON 和 CSV。
2. 导出内容默认包含 Flow、Domain Evidence、IP Profile 和 AgentHealth 摘要。
3. 不导出 payload、HTTP path、请求正文或认证信息。
4. 导出前显示预计记录数、文件大小和敏感信息提示。
5. 导出操作写入本地审计日志，但不记录导出的具体域名列表。

## 9. 信息架构与交互

```text
ZimaOS
└── ZimaScope
    ├── Overview
    ├── Flows
    ├── Endpoints
    ├── Domains
    └── Settings
```

### 9.1 Overview

用户在 10 秒内应能回答：当前是否有异常流量、主要流向哪里、是否存在采集异常。

页面顺序：实时速率卡片 → 趋势图 → Top Domains/Endpoints → 地域与 ASN → 最近 Flow → AgentHealth。

### 9.2 Flows

默认按 `last_seen` 倒序。实时模式每秒增量更新，用户开始筛选、排序或查看详情后暂停自动重排，避免列表跳动。

### 9.3 空状态与降级状态

- 无流量：提示生成测试流量和检查接口。
- eBPF 未挂载：显示具体 hook/interface/error。
- 域名不可见：解释协议盲区，不诱导用户认为功能故障。
- GeoIP 数据过期：基础数据继续展示，并提示更新。
- 数据库只读/磁盘满：实时视图继续工作，历史暂停并记录 Observation Gap。

## 10. 数据模型

### 10.1 FlowRecord

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string | 用户态生成的稳定记录 ID |
| direction | enum | inbound/outbound |
| protocol | enum | tcp/udp/other |
| src_ip/dst_ip | IP | 地址 |
| src_port/dst_port | u16 | 端口；无端口协议为 null |
| interface | string | Device Boundary 接口 |
| packets_in/out | u64 | 双向包数；方向记录可简化为 packets |
| bytes_in/out | u64 | 双向字节数；方向记录可简化为 bytes |
| first_seen/last_seen | timestamp | 观察窗口 |
| domain | string? | Associated Domain |
| domain_evidence | enum? | dns/tls_sni/http_host |
| domain_confidence | enum? | direct/inferred/none |
| ip_profile_id | string? | 目标 IP Profile |
| application_identity_id | string? | P1 |
| end_reason | enum? | timeout/fin/rst/unknown；P1 增强 |

### 10.2 DomainObservation

| 字段 | 说明 |
|---|---|
| domain | 规范化域名 |
| evidence | DNS、TLS SNI 或 HTTP Host |
| observed_at | 观察时间 |
| addresses | 关联 IP 列表 |
| expires_at | DNS TTL 或产品缓存期限 |
| client_context | 用于降低共享 DNS 关联误差的本机上下文 |

### 10.3 IPProfile

包含 IP、address_scope、country、region、city_approximate、asn、organization、database_version 和 enriched_at。

### 10.4 AgentHealth

包含服务状态、启动时间、接口 attach 状态、map 条目/容量、evictions、解析失败、RingBuf/PerfEvent 丢失、数据库状态、GeoIP 状态和 Observation Gap。

## 11. 数据保留与聚合

- 实时 Flow：内存中保存活跃项和短期关闭项。
- 详细历史：默认 7 天，可设置 1/7/30 天。
- 默认磁盘配额：由 ZimaOS 产品团队按最低硬件确认；达到 80% 提示，达到 100% 删除最旧记录。
- 长周期图表使用分钟/小时聚合，不扫描全部 FlowRecord。
- DomainObservation 遵守 TTL；历史展示可以保留“当时观察到的关联”，但不得用于推断 TTL 之后的新 Flow。
- 用户关闭历史后，只保留实时内存状态，不写 Flow 历史数据库。
- 清除历史必须删除 Flow、DomainObservation、聚合和导出临时文件。

## 12. 技术方案约束

### 12.1 推荐架构

```text
Linux TC ingress/egress
        |
Aya eBPF parser + bounded maps
        |
ZimaScope daemon
  ├── map polling and aggregation
  ├── DNS/SNI/Host bounded event processing
  ├── domain association cache
  ├── offline GeoIP/ASN enrichment
  ├── SQLite history and rollups
  └── local Unix socket API
        |
ZimaOS backend/UI
```

### 12.2 实现约束

- eBPF 侧使用 `no_std`、定长 `#[repr(C)]` POD 结构体。
- 任何 header/payload 访问必须进行 verifier 可证明的边界检查。
- Flow 统计优先使用有界 LRU/per-CPU map，避免逐包上送用户态。
- 域名事件只复制严格受限的必要字节，立即在用户态解析并丢弃原始片段。
- daemon 不监听公网端口；ZimaOS 通过 Unix socket 或受控本地接口访问。
- 不依赖内核模块，不要求编译目标机器的 kernel headers。
- 服务退出、升级或禁用时必须清理 TC attachment，避免残留 qdisc/filter。
- 采集异常不得影响设备正常网络转发。

### 12.3 建议代码结构

```text
zimascope/
├── zimascope-ebpf/       # TC hooks, parsers, maps
├── zimascope-common/     # shared POD types
├── zimascoped/          # loader, aggregation, enrichment, storage, API
├── zimascope-ui/         # ZimaOS UI integration
├── xtask/               # build and packaging
└── tests/               # netns/veth integration and fixtures
```

采集架构决策见 `docs/adr/0001-map-aggregation-and-single-collector.md`，Rust ABI、`Collector` 接口与内部 struct 设计见 `docs/design/rust-collector.md`。

## 13. 非功能需求

### 13.1 性能

CPU 为 V1 硬性验收指标，必须在 ZimaOS 最低支持硬件上达到：

- 在默认功能开启和标准负载下，ZimaScope 总体增量 CPU 使用率最高不超过单个逻辑核的 1%。
- 总体增量 CPU 包括 daemon 用户态开销以及可归因于 eBPF 采集的内核态开销，以启用 ZimaScope 前后的基线对比测量。
- 标准负载的流量速率、PPS、Flow 数量、包大小分布和测量窗口必须在首个性能基准提交中固化，后续版本不得放宽该口径。
- 常驻内存不超过 100 MiB；默认配置目标低于 64 MiB。
- eBPF map 内存有明确上限，默认 Flow 容量不超过 65,536。
- UI 概览查询 P95 小于 500 ms；实时指标延迟小于 2 秒。
- 服务启动并完成 attach 小于 5 秒。
- 数据库写入不得对网络数据路径产生背压。

### 13.2 稳定性

- daemon 崩溃不能影响网络连通性。
- 数据库损坏时能够隔离损坏文件并恢复实时采集。
- 接口消失、改名或默认路由变化时自动重试，并生成 Observation Gap。
- 高频流量下允许统计近似，但必须暴露 eviction/drop 指标。

### 13.3 兼容性

- 支持 ZimaOS 官方维护的内核版本和架构矩阵。
- 发布前至少覆盖最低支持内核、当前稳定内核和下一候选内核。
- 支持常见物理网卡、bridge、Docker bridge 和 bond 的基础场景。
- 不支持的 NIC offload 或 hook 模式必须可回退并在 UI 解释。

### 13.4 安全与隐私

- 默认不采集或持久化 payload。
- HTTP 只提取 Host，不记录 path、query、Cookie、Authorization 或正文。
- 域名和 IP 历史视为敏感数据，仅授权的 ZimaOS 管理员可访问。
- API 使用 ZimaOS 现有身份和权限体系，不另设弱口令。
- eBPF 加载所需 capability 应最小化；加载后尽可能降低用户态权限。
- GeoIP 更新包和 ZimaScope 发布包必须验证签名或校验值。
- 导出文件由用户主动生成，并明确提示其中包含网络活动元数据。

## 14. API 需求

内部 API 建议包含：

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/v1/status` | AgentHealth 与当前配置摘要 |
| GET | `/v1/overview` | 指定时间范围的概览 |
| GET | `/v1/flows` | Flow 搜索、过滤和分页 |
| GET | `/v1/flows/{id}` | Flow 详情 |
| GET | `/v1/endpoints` | Endpoint 聚合 |
| GET | `/v1/endpoints/{ip}` | Endpoint 详情 |
| GET | `/v1/domains` | Domain 聚合 |
| GET | `/v1/domains/{domain}` | Domain 详情 |
| GET/PUT | `/v1/settings` | 读取或修改设置 |
| POST | `/v1/export` | 创建本地导出任务 |
| DELETE | `/v1/history` | 清除历史；需要再次确认 |

API 必须支持时间范围、排序、游标或稳定分页，并对高基数字段设置合理上限。

## 15. 可观测性

ZimaScope 必须能够观察自身：

- 各接口 TC hook 状态。
- map 容量、当前条目和淘汰数。
- 每类协议解析成功/失败数。
- 域名事件产生、解析、关联和丢弃数。
- 数据库队列长度、写入失败和磁盘配额。
- GeoIP 命中率和数据库版本。
- daemon CPU、RSS 和运行时间。
- 每个 Observation Gap 的开始、结束和原因。

日志默认不包含完整域名/IP 列表；调试日志必须显式启用并自动过期。

## 16. 测试计划

### 16.1 单元测试

- Ethernet/VLAN/IPv4/TCP/UDP 边界解析。
- 截断包、非法 header length、IP fragmentation。
- 网络/主机字节序转换。
- POD 结构体大小、对齐和字段 offset。
- DNS name compression、TTL 和响应映射。
- TLS ClientHello/SNI 边界与分片失败路径。
- Domain 规范化与关联过期。
- IP address scope 分类。

### 16.2 Linux 集成测试

使用 network namespace + veth 构建可重复环境：

- 产生 TCP/UDP 入站和出站流量并核对方向。
- 使用 `curl`、DNS 查询和 TLS 服务核对域名证据。
- 模拟 map 满、接口删除、服务重启和数据库只读。
- 验证服务停止后网络正常且 attachment 被清理。
- 验证 bridge/physical 默认配置不会明显双计数。

### 16.3 性能测试

- 1/10/100/1000 Mbps 阶梯压测。
- 小包高 PPS 和大包吞吐测试。
- 高 Flow cardinality 与短连接风暴。
- 域名观察开启/关闭对 CPU 的差异。
- 对比启用前后的系统 CPU 基线，分别记录 daemon 和 eBPF 可归因开销，验证标准负载下最高不超过单个逻辑核的 1%。
- UI 大时间范围查询和保留清理。

### 16.4 兼容性测试

- ZimaOS 支持的不同硬件与内核。
- Intel/Realtek 等主要网卡驱动。
- Docker bridge、bond、VLAN、VPN 共存。
- BTF 不可用、TC 不可用和 capability 不足的降级提示。

## 17. V1 验收标准

1. 在支持的 ZimaOS 设备上安装后 5 秒内开始显示实时流量。
2. 测试环境产生的 IPv4 TCP/UDP 流量方向、IP、端口、packets 和 bytes 与基准工具误差在约定范围内。
3. 传统 DNS + HTTPS 测试能够显示 DNS 关联或 TLS SNI，并正确标注 evidence。
4. DoH/ECH 或无域名测试不得展示伪造的“请求域名”。
5. 公网 IP 可离线展示国家/地区、ASN、组织和数据库更新时间。
6. 私网和保留地址不会被错误显示为公网地理位置。
7. 用户可以按方向、IP、端口、协议、域名、国家和 ASN 搜索过滤。
8. 默认历史保留策略和磁盘配额正常执行。
9. 暂停服务后不再采集；清除历史后相关记录和聚合均被删除。
10. daemon 异常退出、map 满或数据库失败时不影响网络连通。
11. UI 明确显示 attach 失败、事件丢失和 Observation Gap。
12. 导出不包含 payload、HTTP path、认证 header 或正文。
13. 在最低支持硬件和标准负载下，ZimaScope 总体增量 CPU 使用率最高不超过单个逻辑核的 1%，并达到内存和响应时间指标。

## 18. 成功指标

### 用户价值指标

- 启用用户中，能够成功看到 Flow 的比例。
- 从概览进入 Endpoint/Domain 详情的使用率。
- 支持工单中，通过 ZimaScope 导出缩短定位时间的比例。
- 用户在一次会话中成功回答“最大流量去向”的任务完成率。

### 产品质量指标

- eBPF attach 成功率。
- Flow map eviction 率。
- Domain 可见率，按 DNS/SNI/Host 分解。
- Observation Gap 时长占比。
- daemon 崩溃率和升级失败率。
- 最高及平均增量 CPU、RSS 和每日磁盘增长量。

Domain 可见率只能作为能力指标，不能通过扩大 payload 采集或误关联来追求数值。

## 19. 预期 Commit 记录

```text
docs: record collector architecture and rust data model
chore: bootstrap zimascope workspace and shared types
feat(ebpf): collect ipv4 tcp udp flows at the device boundary
feat(agent): aggregate flow maps and expose health metrics
feat(domain): associate dns tls sni and http host evidence
feat(enrichment): add offline geoip and asn profiles
feat(storage): persist flow history and time rollups
feat(api): expose local status overview flow endpoint and domain APIs
feat(ui): add overview flows endpoints domains and settings views
feat(privacy): add collection controls retention cleanup and local export
test: add parser network namespace and failure-mode coverage
perf: enforce the 1 percent cpu budget on the minimum hardware profile
chore: add zimaos service packaging upgrade and uninstall cleanup
```

## 20. 风险与应对

| 风险 | 影响 | 应对 |
|---|---|---|
| DoH/DoT/ECH 导致域名不可见 | 用户认为功能不准确 | 展示 evidence、可见率和具体盲区，不做虚假推断 |
| 共享 CDN IP 导致 DNS 误关联 | 错误域名展示 | 关联带 TTL 和 client context，允许多候选并标记 Inferred |
| bridge/physical 双重采集 | 流量翻倍 | Device Boundary 模型、默认排除虚拟接口、配置冲突提示 |
| 高基数 Flow 撑满 map | 数据缺失 | 有界 LRU、eviction 指标、top-N 与聚合策略 |
| 不同内核/驱动行为差异 | attach 或统计失败 | 官方兼容矩阵、自动探测、fallback 和 CI/设备测试 |
| TLS parser 增加 verifier/CPU 压力 | 性能退化 | eBPF 仅截取有限字节，用户态解析，可独立关闭 |
| 网络元数据涉及隐私 | 信任与合规风险 | 本地优先、最小采集、权限控制、明确导出提示 |
| GeoIP 不准确或过期 | 用户误判 | 强调近似位置、优先 ASN、显示数据库版本 |
| daemon 权限过高 | 安全风险 | Unix socket、最小 capability、加载后降权与安全审计 |

## 21. 待产品团队确认

以下事项需要在实现相关功能前确定：

1. ZimaScope 是默认启用，还是由用户首次进入后启用。
2. V1 是否将 TLS SNI 纳入 P0；若延期，首版域名主要来自 DNS。
3. 默认详细历史是 7 天还是 30 天，以及最低硬件磁盘配额。
4. ZimaOS 当前可复用的 App/container identity 数据源。
5. 最低支持硬件、内核和主要网卡型号。
6. GeoIP/ASN 数据供应商、更新许可和离线分发方式。
7. 是否需要支持用户选择多个 Device Boundary 接口。
8. 导出诊断包是否需要内置脱敏选项，例如哈希内网 IP 或域名。

## 22. 推荐立项边界

建议按以下边界控制实现规模：

- V1 只监控 ZimaOS 设备本机边界，不做全局局域网旁路分析。
- V1 只采集元数据，不保存 payload。
- V1 不承诺所有连接都有域名。
- V1 不做阻断、限速或云端管理。
- Application Identity、IPv6 和 TCP 深度质量指标进入 V1.1。

在该边界下，ZimaScope 能形成完整、可信且可交付的产品闭环，同时保留向应用归属和安全洞察演进的空间。
