# Z-Scope 前端复用方案调研

调研日期：2026-09-11

## 结论

如果当前第一目标是“尽量不自研监控前端，同时尽快得到成熟、漂亮、可交互的监控体验”，V1 建议采用 **Grafana OSS 作为受管 sidecar，并通过预置 dashboard 复用整套 UI**。

推荐组合：

- Z-Scope Rust daemon 继续拥有采集、聚合、历史记录和权限边界。
- Grafana 作为独立进程或容器运行，由 ZimaOS 反向代理到同源路径；优先直接打开完整 dashboard，也可使用 iframe/kiosk 模式嵌入。
- 低基数时间序列通过 Prometheus/OpenMetrics 兼容端点提供；Top N、健康状态和有限结果集通过本地 JSON REST API 配合 Grafana Infinity datasource 提供。
- dashboard、datasource 和权限设置全部 provision，用户安装后无需手工配置。
- V1 使用 1 秒自动刷新即可满足 PRD 的“用户态默认每秒生成展示快照”；不要一开始就开发 Grafana Live streaming plugin。

这条路线复用了完整的 dashboard 编辑器、时间范围、自动刷新、变量、表格、图表、主题和响应式布局。主要代价是增加一个 Grafana 运行时、嵌入认证配置，以及接受 Grafana 的产品外观和 AGPL-3.0 合规义务。

如果“必须像 ZimaOS 原生页面、不能看起来像 Grafana”比“最少前端代码”更重要，则第二选择是 **React 壳 + Perses 可嵌入组件**。Perses 的 Apache-2.0 许可证和明确的嵌入 API 更适合产品内集成，但 Flow 搜索、Domain Evidence、隐私开关和导出仍需编写业务页面，复用程度明显低于整套 Grafana。

## 关键约束

Z-Scope 的 UI 不只是常规指标看板。PRD 还要求 Flow 搜索/分页/详情、Domain Evidence、Observation Gap、隐私控制和导出。因此任何通用 dashboard 都只能直接覆盖“概览、趋势、Top N、健康”部分；越接近完整产品体验，越需要少量领域 UI。

浏览器和第三方 dashboard 服务不能直接消费 Unix socket。建议 Unix socket 保留为 daemon 内部控制面，同时提供仅绑定 loopback 或仅经 ZimaOS 反向代理可达的 HTTP API。不要把每个 IP、域名或五元组编码为 Prometheus label；Prometheus 官方文档明确提醒每个唯一 label 组合都会形成新的时间序列，高基数会显著增加存储量。[Prometheus naming and labels](https://prometheus.io/docs/practices/naming/)

因此数据面应拆成：

| 数据 | 建议接口 | 前端用途 |
|---|---|---|
| 入站/出站速率、总量、活跃 Flow 数、可见率、丢事件 | Prometheus/OpenMetrics 或小型 JSON time-series API | 趋势、Stat、Gauge、健康面板 |
| Top Endpoint/Domain/ASN/Country | 有时间范围与 limit 的 JSON API | Bar chart、table、pie/treemap |
| Flow 列表 | 服务端过滤、排序、游标分页的 JSON API | Table；严禁一次返回全量历史 |
| Flow/Endpoint/Domain 详情 | 按 ID/key 查询的 JSON API | Drill-down/detail |
| 秒级更新 | 先用 1 秒 polling；确有需要再加 WebSocket/SSE | 避免过早引入 streaming plugin |

## 对比

下表中的“资源占用”是按部署构成做的相对判断，不是跨项目基准测试；这些项目的官方文档没有给出可直接横向比较的固定内存数字。

| 方案 | 许可证 | 可直接复用程度 | 实时能力 | 后端数据契约 | 定制/主题 | 相对资源占用 | Z-Scope 适配度 |
|---|---|---:|---|---|---|---|---|
| Grafana OSS + provisioned dashboards | AGPL-3.0 | 很高 | 自动刷新；Grafana Live 可用 WebSocket 推送 | Prometheus 等原生 datasource；Infinity 可查 JSON/REST | 深色/浅色、dashboard JSON、变量、插件；深度品牌化有限 | 中高：额外 Grafana 服务与 SQLite；官方最低建议 512 MB / 1 CPU core | **最佳短期选择** |
| Perses standalone/embedded | Apache-2.0 | 中高 | refresh interval；主要按查询刷新 | 原生偏 Prometheus/Loki/Tempo/Pyroscope；可扩展插件 | React + MUI + ECharts，嵌入和主题控制更自然 | standalone 为中等；仅嵌入 npm 包则无额外后端但 JS 依赖较多 | **最佳原生集成备选** |
| SigNoz frontend/整套平台 | 核心大部分 MIT，`ee/` 另有企业许可证 | 整套部署高，单独前端低 | 平台内实时/近实时查询 | 强依赖 SigNoz backend、OpenTelemetry 数据模型和完整安装栈 | UI 完整漂亮，但不是稳定的通用嵌入 SDK | 很高：完整 observability backend/存储栈；官方 Docker 前提至少 4 GB | 不推荐 |
| Netdata Agent dashboard | GPL-3.0 | 对 Netdata 指标很高，对 Z-Scope 很低 | 强，Agent dashboard 面向实时节点指标 | Netdata 自有 chart/context/API 模型 | 现成亮/暗主题；产品级改造空间有限 | 中高：额外运行完整 Netdata Agent，且与现有采集重复 | 不推荐 |
| Refine + UI kit | MIT | 中 | `liveProvider` 可接实时 provider | REST/GraphQL CRUD data provider，需自行定义全部资源 | 高；可选 Ant Design/MUI 等 | 低中：纯 Web app | 仅适合业务页面骨架 |
| Apache ECharts（或 Recharts） | Apache-2.0（Recharts 为 MIT） | 低 | ECharts 支持动态与流式数据 | 任意 JS 数据，由应用负责转换 | 很高 | 低；可按需打包 | 图表层备选，不是 dashboard 复用方案 |

所有候选项目在调研日均有近期主分支更新，未处于 archived 状态；项目活跃度本身不是淘汰项。可从各自官方仓库查看最新状态：[Grafana](https://github.com/grafana/grafana)、[Perses](https://github.com/perses/perses)、[SigNoz](https://github.com/SigNoz/signoz)、[Netdata](https://github.com/netdata/netdata)、[Refine](https://github.com/refinedev/refine)、[Apache ECharts](https://github.com/apache/echarts)。

## 方案详评

### 1. Grafana OSS：推荐

Grafana 是完整的 observability dashboard 产品，不只是 chart library。它原生提供 dashboard、templating variables、混合 datasource 和大量 visualization；这正是最大化前端复用所需要的层级。[Grafana repository](https://github.com/grafana/grafana)

**嵌入与交付**

- Grafana 支持 dashboard/panel embed；嵌入视图仍需有 Viewer 权限，除非自托管实例启用 anonymous access。[Share dashboards and panels](https://grafana.com/docs/grafana/latest/dashboards/share-dashboards-panels/)
- `allow_embedding` 默认为关闭；关闭时 Grafana 会发送 `X-Frame-Options: deny`。如果使用 iframe，必须显式开启，并同时正确处理 cookie、同源代理和 WebSocket 转发。[Grafana configuration](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/)
- Grafana 支持用配置文件 provision datasource 和 dashboard，适合随 Z-Scope 版本发布只读 dashboard JSON，而不是让最终用户手工搭建。[Provision Grafana](https://grafana.com/docs/grafana/latest/administration/provisioning/)
- 实际集成时优先让 ZimaOS 反代 `/zimascope/` 到 Grafana，并使用同源认证；若只是打开独立 ZimaOS 应用页面，直接使用 Grafana kiosk/只读视图会比 iframe 更少出错。

**数据接入**

- 聚合指标最适合 Prometheus/OpenMetrics 数据源。
- Grafana Infinity datasource 是 Grafana 官方维护的通用 REST datasource，可读取 JSON、CSV、TSV、XML 和 GraphQL，适合作为 Z-Scope 尚无原生 datasource 时的桥接层。官方同时说明它不适合处理大量数据，因此 API 必须返回 Top N、单页 Flow 或预聚合结果，不能把完整 Flow 历史交给它。[Infinity datasource docs](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/) [Infinity repository and Apache-2.0 license](https://github.com/grafana/grafana-infinity-datasource)
- 如果后续确实需要 WebSocket push，Grafana Live 是基于 Pub/Sub 的 soft real-time 引擎，backend datasource plugin 可以向 panel streaming；它会增加插件开发和连接管理复杂度。[Grafana Live](https://grafana.com/docs/grafana/latest/setup-grafana/set-up-grafana-live/)

**适合与不足**

- 优点：开箱即用的监控视觉语言最成熟；overview、Top N、时间范围、健康提示、表格和 drill-down 可通过 dashboard 配置完成；几乎不需要自建设计系统。
- 不足：复杂 Flow 浏览器、Domain Evidence 的解释性 UI、隐私设置和导出流程用 dashboard 表达会比较生硬。V1 可以先用 table + dashboard link；体验要求提高后再补一个小型领域页面或 Grafana app plugin。Grafana 官方插件体系提供 panel、datasource 和 app plugin 三种扩展面。[Grafana plugin types](https://grafana.com/developers/plugin-tools/key-concepts/plugin-types-usage)
- 资源：Grafana 官方安装文档给出的最低建议是 512 MB 内存和 1 CPU core，并说明实际需求取决于功能和负载；这对最低规格 ZimaOS 设备仍需实测。[Grafana installation requirements](https://grafana.com/docs/grafana/latest/setup-grafana/installation/)
- 许可证：Grafana 主仓库为 AGPL-3.0。[Grafana LICENSE](https://github.com/grafana/grafana/blob/main/LICENSE) 独立、未修改的 sidecar 比 fork/深改 Grafana 更容易隔离工程边界，但分发、修改和网络使用相关义务应由项目方做正式许可证审查。

### 2. Perses：最佳原生集成备选

Perses 是面向 observability 的 CNCF 项目，采用 Apache-2.0。[Perses repository](https://github.com/perses/perses) [CNCF project page](https://www.cncf.io/projects/perses/)

它与 Grafana 的关键差异不是图表多少，而是官方明确把 UI 拆成可供外部应用组合的 npm packages。`@perses-dev/components`、`dashboards`、`plugin-system` 等可嵌入自己的 React 应用；官方给出了将单个 panel 嵌入 React 的完整示例。[Perses UI packages](https://github.com/perses/perses/blob/main/ui/README.md) [Embedding panels](https://github.com/perses/perses/blob/main/docs/embedding-panels.md)

- 嵌入栈当前基于 React 18、MUI、TanStack Query 和 ECharts，主题可以通过 MUI theme 与 Perses chart theme 控制。
- 官方嵌入示例需要装配多个 Provider，且文档明确表示团队仍在减少所需 dependencies/providers；这说明嵌入 API 是正式方向，但目前还不是极简组件。[Embedding panels](https://github.com/perses/perses/blob/main/docs/embedding-panels.md)
- 默认 datasource 生态偏 Prometheus、Loki、Tempo 和 Pyroscope。Z-Scope 若使用 Perses，聚合指标接入自然，但 Flow/Domain 的 REST 查询仍需自定义 datasource/plugin 或业务组件。
- 前端 packages 会带入 MUI、ECharts、TanStack、react-grid-layout 等依赖，bundle 不会像单一 chart library 那样小；但“嵌入模式”无需再运行完整 dashboard server。[Perses shared packages](https://github.com/perses/shared)

Perses 更适合这样的目标：Z-Scope 最终要成为视觉上完全属于 ZimaOS 的产品，同时愿意自行实现约一半领域交互。若当前重点是最快出成品，它不如 Grafana；若重点是长期产品整合和宽松许可证，它优于 Grafana。

### 3. SigNoz：不建议拆前端复用

SigNoz 的页面完整、美观，也覆盖 metrics/logs/traces/dashboard，但其 frontend 是 SigNoz 产品前端，不是面向第三方应用发布的嵌入式 dashboard SDK。官方 frontend README 要求先运行 SigNoz backend，并通过 `VITE_FRONTEND_API_ENDPOINT` 指向它；目录中包含大量 SigNoz API clients、page containers 和产品状态管理。[SigNoz frontend README](https://github.com/SigNoz/signoz/blob/main/frontend/README.md)

- 自托管 SigNoz 面向完整 OpenTelemetry observability 平台，而 Z-Scope 已有自己的 Rust collector 和领域模型。为复用 UI 而适配 SigNoz ingestion/query schema，会把项目变成 SigNoz 的数据生产者和部署包装，而不是轻量本地服务。[SigNoz repository](https://github.com/SigNoz/signoz) [Self-host documentation](https://signoz.io/docs/install/self-host/)
- 官方 Docker 安装文档要求至少为 Docker 分配 4 GB 内存，仅这一前提就明显高于 Grafana 的官方最低建议，也不符合低规格设备上的轻量目标。[SigNoz Docker installation](https://signoz.io/docs/install/docker/)
- SigNoz 核心仓库大部分代码按 MIT Expat 发布，但 `ee/` 和 `cmd/enterprise/` 使用各自许可证，复用时必须逐目录确认。[SigNoz LICENSE](https://github.com/SigNoz/signoz/blob/main/LICENSE)
- 单独 fork frontend 会继承紧耦合 API、升级合并和品牌改造成本；部署整套平台则资源和运维成本明显偏离 Z-Scope 的“轻量、本地优先”。

### 4. Netdata dashboard：不建议

Netdata Agent 自带非常成熟的实时节点 dashboard，本地可从 `http://NODE:19999` 访问，断网时使用 bundled dashboard；它也提供 Agent REST API。[Netdata dashboards](https://github.com/netdata/netdata/blob/master/docs/dashboards-and-charts/README.md) [Netdata Agent API](https://github.com/netdata/netdata/blob/master/src/web/api/README.md)

但它的 UI 与 Netdata Agent 的 chart/context/alert 模型是一体的。复用完整 UI 意味着同时运行 Netdata Agent，并把 Z-Scope 数据改造成 Netdata metrics/functions；这与现有 eBPF collector 重复，且 Flow、Domain Evidence 等领域对象不自然。官方 UI 主题主要是 light/dark，不能等同于可嵌入组件库。[Netdata themes](https://github.com/netdata/netdata/blob/master/docs/dashboards-and-charts/themes.md)

Netdata 主仓库为 GPL-3.0。[Netdata LICENSE](https://github.com/netdata/netdata/blob/master/LICENSE) 它更适合“直接采用 Netdata 作为监控产品”，不适合“保留 Z-Scope backend，只借用前端”。

### 5. Refine / Ant Design Pro 类框架：只适合补齐业务页

Refine 是 MIT 的 headless React framework，提供 data provider、路由、CRUD、表格、过滤、认证和 `liveProvider` 实时订阅抽象，并可组合 Ant Design 等 UI 框架。[Refine repository](https://github.com/refinedev/refine) [Data providers](https://refine.dev/docs/data/data-provider/) [Realtime](https://refine.dev/core/docs/realtime/live-provider/)

它可以明显减少 Flow 列表、筛选、详情、设置页和导出操作的样板代码，但不会提供监控 dashboard 的指标语义、panel 配置、时间范围联动或现成漂亮看板。把它作为 Grafana 旁边的“小型领域控制台”有价值；把它作为唯一前端，仍需自行设计大部分监控体验。

### 6. ECharts / Recharts：只能复用可视化层

Apache ECharts 提供 Canvas/SVG、动态数据、WebSocket 流式更新、大数据增量渲染、移动端交互和丰富图表类型，许可证为 Apache-2.0。[ECharts features](https://echarts.apache.org/en/feature.html) [ECharts repository](https://github.com/apache/echarts)

它是 Perses 的底层 chart engine，也适合未来自研页面时按需使用。但它不提供 dashboard shell、数据查询、时间范围、过滤联动、权限、表格或设置页，因此不能实现“尽量不写前端”的目标。Recharts 同理，只是更 React-native，采用 MIT。[Recharts repository](https://github.com/recharts/recharts)

## 推荐落地路径

### Phase 1：Grafana-first MVP

1. 把 Grafana OSS 作为 Z-Scope 安装包中的独立受管服务，使用独立 SQLite 数据库和只读 Viewer。
2. 由 ZimaOS 反向代理 Grafana 与 Rust HTTP API；两者只监听本地或私有网络，不把 daemon API 直接暴露到公网。
3. provision 一个 datasource 和一组版本化 dashboard JSON，禁止用户安装后再做必需配置。
4. 先提供四个 dashboard：Overview、Flows、Endpoints & Domains、Collector Health。
5. Overview 的趋势使用低基数 metrics；Flows/Top N 使用有严格 limit、过滤和时间范围的 JSON API。
6. 默认 1 秒刷新当前数据，历史视图按时间范围降低刷新频率。只有验证 polling 成为瓶颈后，才开发 Grafana streaming datasource。
7. 在发行物中保留 Grafana 与 Infinity 的许可证、版权信息和对应源码获取方式，并让法务/发行负责人确认 AGPL 合规流程。

### Phase 2：只补通用 dashboard 难以表达的部分

若用户测试证明 Flow 搜索、Evidence 解释或隐私设置在 Grafana 内体验不足，再增加一个很小的 React 页面；可以用 Refine 复用 REST 表格/过滤，用 ECharts 或 Perses panel 复用图表。不要在 V1 一开始重写 Grafana 已经成熟解决的概览和趋势页面。

### 转向 Perses 的触发条件

出现以下任一条件时，优先做 Perses spike，而不是继续深改 Grafana：

- ZimaOS 要求完全统一的导航、品牌、交互和组件规范。
- 产品不能接受额外 Grafana 服务，或 AGPL 分发流程不可接受。
- 领域详情页占到主要使用路径，Grafana dashboard 只剩少量图表。
- 团队愿意维护 React 应用，并接受 Flow/Domain/设置页仍需自研。

## 最小验证原型

在正式决定前，建议只做一个 2–3 天的无承诺 spike：

- 使用静态 fixture 或 mock HTTP，而不是改动 collector。
- provision 一个 Overview dashboard：双向速率、活跃 Flow、Top Endpoint、Top Domain、Observation Gap。
- provision 一个 Flow table：服务端 limit/filter，点击跳到详情 dashboard。
- 验证 ZimaOS 反向代理下的同源认证、iframe/kiosk、WebSocket 转发和移动端布局。
- 记录冷启动时间、空闲内存、1 秒刷新 CPU、安装包增量和 dashboard 首屏时间；只有实测才能回答目标硬件上的真实资源成本。

通过标准应是：无需修改 Grafana 源码即可覆盖 P0 概览与大部分 Flow 浏览，并且目标最低硬件上资源可接受。若必须 fork Grafana frontend 才能达到基本体验，应立即改评 Perses，而不是维护长期 fork。
