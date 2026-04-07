# Flux XDR

Flux 是一个面向安全运营场景的智能安全运营平台：前端提供聊天式工作台与 Playbook 卡片，后端基于 FastAPI、LLM、多轮上下文和 XDR/OpenAPI 对接能力，把“查询、研判、审批、处置、闭环”串成一套可追溯流程。

这份 README 以当前仓库代码为准，优先回答三个问题：
- 现在到底有哪些功能模块已经落地
- 每个模块真实调用了哪些接口、产出什么数据
- 统计类能力的口径、限制和数据来源是什么

更完整的操作说明仍保留在 [User_Manual.md](User_Manual.md)，接口原始资料位于 [docs/api-ref](docs/api-ref)。

## 1. 平台概览

- 后端入口：`backend/app/main.py`
- 前端入口：`frontend/index.html` + `frontend/app.js`
- 运行形态：FastAPI 后端挂载静态前端，默认使用 SQLite 持久化
- AI 执行主链路：`IntentParser -> IntentPipeline(IR/Lint/Safety) -> SkillRegistry -> Payload`
- 自动化能力：Playbook 异步执行、Workflow 定时调度、审批闭环、Webhook 通知

当前主能力包括：
- XDR 凭证登录与连通性探测，支持联动码或 AK/SK
- 多 LLM 供应商接入：OpenAI、智谱、DeepSeek、自定义兼容端点
- 多轮对话 Copilot：事件查询、详情、实体情报、处置、封禁、日志统计
- 安全分析：事件趋势、类型分布、处置成果、重点事件解读、告警分类
- Playbook Hub：今日安全早报、单点告警深度研判、攻击者活动轨迹、核心资产防线透视
- Workflow 闭环：按 CRON 定时拉取高危事件、生成建议、审批、自动处置
- Safety Gate：内置和自定义防误封规则，拦截高危批量模糊操作

## 2. 功能模块

### 2.1 认证接入层

- 入口接口：`/api/auth/probe`、`/api/auth/login`、`/api/auth/status`、`/api/auth/logout`
- 上游 XDR 接口：`POST /api/xdr/v1/incidents/list`
- 认证方式：联动码，或 `access_key + secret_key`
- 核心逻辑：
  - 先用 `incidents/list` 做探活
  - 探活成功后把凭证落库到 `XDRCredential`
  - `status` 会做实时探测，区分“已保存凭证”和“当前服务可达”
- 持久化对象：`XDRCredential`
- 输出形态：JSON 状态结果，供前端登录页和工作台头部使用

### 2.2 系统设置层

- 入口接口：`/api/config/*` 与 `/api/config/safety_gate/*`
- 子模块：
  - LLM 供应商：`/providers`、`/providers/test`
  - ThreatBook：`/threatbook`、`/threatbook/test`
  - 核心资产：`/core-assets`
  - 语义规则：`/semantic-rules`、`/semantic-rules/meta`
  - 安全防线：`/safety_gate/`
- 核心逻辑：
  - 供应商配置落到 `ProviderConfig`，`LLMRouter` 按启用状态和默认供应商路由
  - ThreatBook Key 可来自数据库或环境变量；实体情报未配置 Key 时回退到稳定本地启发式评估
  - 语义规则用于自然语言槽位注入，例如把某些话术直接映射成意图参数
  - 安全防线支持 `ip/domain/cidr` 三类自定义规则，并叠加系统内置公共 DNS、保留网段等保护目标
- 持久化对象：`ProviderConfig`、`ThreatIntelConfig`、`CoreAsset`、`SemanticRule`、`SafetyGateRule`
- 输出形态：JSON 配置数据，供前端设置面板和拦截逻辑使用

### 2.3 AI Copilot 对话执行层

- 入口接口：`POST /api/chat`、`POST /api/chat/stream`
- 主执行链路：
  1. `IntentParser` 做意图分类、时间/等级/状态/序号/封禁参数抽取
  2. 语义规则二次注入参数
  3. `IntentPipeline` 生成 IR，并执行 Lint + Safety Gate
  4. `SkillRegistry` 分发到具体 Skill
  5. 返回统一 Payload：`text`、`table`、`echarts_graph`、`approval_card`、`form_card`、`quick_actions`
- 多轮能力：
  - `SessionState` 存会话参数、索引映射、待确认动作、待提交表单
  - 支持“第 3 个事件”“刚刚那个 IP”“确认/取消”等上下文指代
  - 危险动作会转成审批卡，确认后再执行
- 持久化对象：`SessionState`、`AuditAction`
- 输出形态：
  - `/api/chat` 返回完整 JSON payload 列表
  - `/api/chat/stream` 以 SSE 流式推送文本和卡片

### 2.4 查询与处置 Skills

已注册的查询/处置类 Skill 包括：

| Skill | 主要能力 | 典型输出 |
| --- | --- | --- |
| `EventQuerySkill` | 查询安全事件列表 | 文本总结 + 事件表格 + `events` 序号映射 |
| `EventDetailSkill` | 拉取事件 proof 与关联实体 | 详情文本 + 时间线/证据表格 |
| `EntityQuerySkill` | 查询事件外网实体 / 指定 IP 情报 | 文本总结 + 实体情报表 |
| `EventActionSkill` | 批量更新事件处置状态 | 危险操作确认 + 执行结果文本 |
| `BlockQuerySkill` | 查询封禁策略/是否已封禁 | 文本总结 + 封禁规则表 + 快捷封禁动作 |
| `BlockActionSkill` | 新增网侧封禁规则 | 表单补参/确认卡 + 执行结果 |
| `LogStatsSkill` | 查询网络安全日志总数 | `echarts_graph` 图表 payload |

这一层是日常 Copilot 的主工作面，既支持直接查询，也支持和 Playbook/Workflow 串联。

### 2.5 安全分析 Skills

已注册的统计分析 Skill 包括：

| Skill | 分析主题 | 主要输出 |
| --- | --- | --- |
| `EventTrendSkill` | 安全事件发生趋势 | 文本 + 总体趋势图 + 等级拆分图 + 明细表 |
| `EventTypeDistributionSkill` | 事件类型/研判结论分布 | 文本 + TopN 图表 + 明细表 |
| `EventDispositionSummarySkill` | 事件处置成果 | 文本 + 状态/动作分布图 + 待处置重点事件清单 |
| `KeyEventInsightSkill` | 重点事件解读 | 文本 + 重点事件总表 + 每条事件的深入解读 |
| `AlertClassificationSummarySkill` | 告警分类情况 | 文本 + 一级/二级/三级分类图 + 严重性/状态/方向分布图 |

这些能力主要依赖 `SecurityAnalyticsService` 做分页扫描、字段归一化、本地聚合与 TopN 计算。

### 2.6 Playbook Hub

- 入口接口：
  - `GET /api/playbooks/templates`
  - `POST /api/playbooks/run`
  - `GET /api/playbooks/runs/{run_id}`
  - `POST /api/playbooks/routine-check/block-preview`
  - `POST /api/playbooks/routine-check/block-sources`
- 当前模板：
  - `routine_check`：今日安全早报
  - `alert_triage`：单点告警深度研判
  - `threat_hunting`：攻击者活动轨迹
  - `asset_guard`：核心资产防线透视
- 核心逻辑：
  - 模板参数先经 `playbook/schemas.py` 校验
  - `PlaybookRun` 落库存储输入、上下文、结果、状态
  - 后台线程异步执行，前端通过 run id 轮询详情
  - 某些模板会串联 XDR 事件、告警、资产、封禁、日志统计、ThreatBook 情报和 LLM 摘要
- 持久化对象：`PlaybookRun`
- 输出形态：阶段化运行状态、上下文快照、总结卡片、封禁建议/审批结果

### 2.7 Workflow 闭环

- 入口接口：
  - `GET/POST /api/workflows`
  - `POST /api/workflows/run`
  - `GET /api/workflows/approvals`
  - `POST /api/workflows/approvals/{approval_id}/decision`
- 执行形态：
  - 启动时由 `scheduler.py` 加载 CRON 配置
  - 支持手动触发和定时触发
  - 当前默认流程：查询高危事件 -> 详情/实体并行拉取 -> LLM 生成建议 -> 审批 -> 自动处置 -> Webhook
- 核心逻辑：
  - `WorkflowConfig` 保存策略
  - `WorkflowRun` 保存每次执行上下文和结果
  - `ApprovalRequest` 保存审批卡与审批结果
- 持久化对象：`WorkflowConfig`、`WorkflowRun`、`ApprovalRequest`
- 输出形态：运行上下文、审批卡、处置结果、可选 Webhook 文本通知

## 3. 平台内部 API 分组

前端当前实际调用的后端分组主要是：

- `/api/auth`：XDR 登录、登出、状态探测
- `/api/config`：供应商、ThreatBook、核心资产、语义规则、安全防线
- `/api/chat`：对话执行与 SSE 流式返回
- `/api/playbooks`：模板列表、异步运行、早报封禁预览/执行
- `/api/workflows`：闭环配置、手动触发、审批决策

补充：

- `/` 返回前端主页
- `/assets` 挂载静态前端资源

## 4. 接口矩阵

下表按“内部路由 -> Skill/服务 -> 上游 XDR API -> 输出”梳理当前真实契约。

| 内部路由 | Skill / 服务 | 上游 XDR API | 主要输出 |
| --- | --- | --- | --- |
| `/api/auth/probe` `/api/auth/login` `/api/auth/status` | `APIRequester` + `ConfigService` | `POST /api/xdr/v1/incidents/list` | 认证探测结果、登录状态 |
| `/api/chat` `/api/chat/stream` | `EventQuerySkill` | `POST /api/xdr/v1/incidents/list` | 事件列表表格、上下文索引 |
| `/api/chat` `/api/chat/stream` | `EventDetailSkill` | `GET /api/xdr/v1/incidents/{uuid}/proof` + `GET /api/xdr/v1/incidents/{uuid}/entities/ip` | 详情文本、时间线、证据/实体信息 |
| `/api/chat` `/api/chat/stream` | `EntityQuerySkill` | `GET /api/xdr/v1/incidents/{uuid}/entities/ip` | 外网实体情报表 |
| `/api/chat` `/api/chat/stream` | `EventActionSkill` | `POST /api/xdr/v1/incidents/dealstatus` | 审批卡、处置结果文本 |
| `/api/chat` `/api/chat/stream` | `BlockQuerySkill` | `POST /api/xdr/v1/responses/blockiprule/list` | 封禁策略表、未封禁提示、快捷动作 |
| `/api/chat` `/api/chat/stream` | `BlockActionSkill` | `POST /api/xdr/v1/device/blockdevice/list` + `POST /api/xdr/v1/responses/blockiprule/network` | 参数表单、审批卡、封禁执行结果 |
| `/api/chat` `/api/chat/stream` | `LogStatsSkill` | `POST /api/xdr/v1/analysislog/networksecurity/count` | 日志总数图表 |
| `/api/chat` `/api/chat/stream` | `EventTrendSkill` `EventTypeDistributionSkill` `EventDispositionSummarySkill` | `POST /api/xdr/v1/incidents/list` | 统计文本、图表、明细表 |
| `/api/chat` `/api/chat/stream` | `KeyEventInsightSkill` | `POST /api/xdr/v1/incidents/list` + `GET /api/xdr/v1/incidents/{uuid}/proof` + `GET /api/xdr/v1/incidents/{uuid}/entities/ip` | 重点事件总表、逐条深入解读 |
| `/api/chat` `/api/chat/stream` | `AlertClassificationSummarySkill` | `POST /api/xdr/v1/alerts/list` | 告警分类图表与明细表 |
| `/api/playbooks/run` `/api/playbooks/runs/{run_id}` | `PlaybookService` | `POST /api/xdr/v1/incidents/list` + `POST /api/xdr/v1/alerts/list` + `GET /api/xdr/v1/incidents/{uuid}/proof` + `GET /api/xdr/v1/incidents/{uuid}/entities/ip` + `POST /api/xdr/v1/analysislog/networksecurity/count` + `POST /api/xdr/v1/assets/list` + `POST /api/xdr/v1/device/blockdevice/list` + `POST /api/xdr/v1/responses/blockiprule/network` | 异步运行上下文、阶段性结果、建议报告 |
| `/api/workflows` `/api/workflows/run` `/api/workflows/approvals/*` | `WorkflowService` | `POST /api/xdr/v1/incidents/list` + `GET /api/xdr/v1/incidents/{uuid}/proof` + `GET /api/xdr/v1/incidents/{uuid}/entities/ip` + `POST /api/xdr/v1/incidents/dealstatus` + `POST /api/xdr/v1/device/blockdevice/list` + `POST /api/xdr/v1/responses/blockiprule/network` | Workflow 上下文、审批卡、自动处置结果 |
| `/api/config/core-assets` | `ConfigService`，被 `asset_guard` Playbook 复用 | `POST /api/xdr/v1/assets/list` | 核心资产配置数据、体检输入资产基线 |

补充说明：

- `/api/config/providers/test` 访问的是 OpenAI/智谱/DeepSeek/自定义 LLM API，而不是 XDR。
- `/api/config/threatbook/test` 和实体情报增强访问的是 ThreatBook API，而不是 XDR。

## 5. 统计逻辑与口径

### 5.1 网络安全日志总数

- 数据来源：`POST /api/xdr/v1/analysislog/networksecurity/count`
- 统计方式：直接读取接口返回的 `data.total`
- 图表逻辑：前端展示所需趋势线由本地 `_build_trend()` 根据总量和时间窗均摊生成
- 当前限制：
  - 该趋势不是上游真实逐日/逐小时序列
  - 当用户未指定时间范围时，图表横轴默认按最近 7 天生成展示窗口

### 5.2 安全事件趋势

- 数据来源：`SecurityAnalyticsService.scan_incidents()`，分页调用 `POST /api/xdr/v1/incidents/list`
- 扫描上限：默认最多扫描 `10000` 条事件
- 聚合逻辑：
  - 当时间窗小于等于 48 小时时按小时分桶，否则按天分桶
  - 计算每个时间桶的总数和等级拆分
  - 计算峰值时间桶和峰值数量
- 当前限制：
  - 如果接口总量大于扫描上限，结果会被截断，响应文本会提示
  - 趋势结果以扫描到的快照为准，不代表全量离线仓指标

### 5.3 事件类型分布

- 数据来源：分页扫描 `incidents/list`
- 聚合字段：
  - 主维度：`gptResultLabel`，若缺失则回退 `gptResultDescription`
  - 辅维度：`incidentThreatClass`、`incidentThreatType`
- 高危统计口径：`severityCode >= 3`，即高危和严重
- 输出结果：
  - 研判结论 TopN
  - 高危/严重事件研判 TopN
  - 结论/一级分类/二级分类明细表

### 5.4 事件处置成果

- 数据来源：分页扫描 `incidents/list`
- 聚合字段：`dealStatus` 与 `dealAction`
- 已处置率口径：`{已处置, 已遏制, 接受风险}` 这三类状态之和 / 总事件数
- 待处置重点事件排序：按“严重度 -> 未处置优先 -> 最近发生时间”降序取前若干条
- 当前限制：
  - 这是当前状态快照，不代表历史处置流水
  - 不能从当前接口推出平均处置时长、状态迁移链路等时序指标

### 5.5 重点事件解读

- 数据来源：
  - 先扫描 `incidents/list`
  - 再对选中的重点事件补调 `GET /api/xdr/v1/incidents/{uuid}/proof`
  - 同时补调 `GET /api/xdr/v1/incidents/{uuid}/entities/ip`
- TopN 选择口径：按“严重度 > 未处置优先 > 最近发生时间”排序
- 解读内容：
  - 基础事件信息
  - GPT 研判结论
  - 风险标签
  - 时间线摘要
  - 关联外网实体
  - 建议处置动作
- 当前限制：
  - proof 或 entity 接口失败时会回退到列表字段，并在说明里标注异常

### 5.6 安全告警分类

- 数据来源：`SecurityAnalyticsService.scan_alerts()`，分页调用 `POST /api/xdr/v1/alerts/list`
- 扫描上限：默认最多扫描 `10000` 条告警
- 聚合维度：
  - 一级分类 `threatClassDesc`
  - 二级分类 `threatTypeDesc`
  - 三级分类 `threatSubTypeDesc`
  - 严重性、处置状态、访问方向
- 输出结果：
  - 一级/二级/三级分类 TopN
  - 严重性分布
  - 处置状态分布
  - 访问方向分布
  - 分类明细表

## 6. 数据落库与状态对象

默认数据库优先使用 `data/flux.db`；如果该文件不存在，则兼容历史根目录 `flux.db`。当前主要状态对象如下：

| 模型 | 用途 |
| --- | --- |
| `XDRCredential` | XDR 基础地址、联动码/AKSK、SSL 校验开关 |
| `ProviderConfig` | LLM 供应商配置与模型路由 |
| `ThreatIntelConfig` | ThreatBook Key 与启用状态 |
| `SemanticRule` | 语义规则、匹配模式、槽位映射、优先级 |
| `CoreAsset` | 核心资产台账 |
| `SafetyGateRule` | 自定义防误封规则 |
| `SessionState` | 对话参数继承、序号映射、待确认动作、待提交表单 |
| `AuditAction` | 危险操作审计轨迹 |
| `PlaybookRun` | Playbook 输入、上下文、结果、错误、状态 |
| `WorkflowConfig` | Workflow 的名称、CRON、等级范围、审批要求、Webhook |
| `WorkflowRun` | 每次 Workflow 执行上下文和结果 |
| `ApprovalRequest` | 审批卡、审批状态、审批人、决策结果 |

## 7. 部署、运行与验证

### 7.1 本地开发启动

推荐直接使用现成脚本：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
bash scripts/run_dev.sh
```

`scripts/run_dev.sh` 会自动：

- 设置 `PYTHONPATH=$(pwd)/backend`
- 默认把 `DB_PATH` 指向 `data/flux.db`
- 执行幂等迁移 `scripts/migrate_db.py`
- 启动 `uvicorn app.main:app --reload`

启动后访问 [http://127.0.0.1:8000](http://127.0.0.1:8000)。

### 7.2 手动迁移与手动启动

```bash
source .venv/bin/activate
export PYTHONPATH=$(pwd)/backend
python scripts/migrate_db.py
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

如需显式指定数据库文件：

```bash
source .venv/bin/activate
export PYTHONPATH=$(pwd)/backend
python scripts/migrate_db.py --db-path /absolute/path/to/flux.db
```

### 7.3 测试

```bash
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=$(pwd)/backend
python scripts/migrate_db.py
python3 -m unittest discover -s backend/app/tests -p 'test_*.py'
```

只跑单个测试文件：

```bash
source .venv/bin/activate
export PYTHONPATH=$(pwd)/backend
python3 -m unittest backend/app/tests/test_workflow.py
```

### 7.4 Docker 部署

`docker-compose.yml` 会把数据库持久化到宿主机 `./data/flux.db`，容器内路径为 `/app/data/flux.db`。

```bash
docker compose up --build -d
docker compose logs -f
```

访问 [http://127.0.0.1:8000](http://127.0.0.1:8000)。

停止服务：

```bash
docker compose down
```

容器内执行测试：

```bash
docker compose run --rm flux python -m unittest discover -s backend/app/tests -p 'test_*.py'
```

### 7.5 PyInstaller 打包

项目自带脚本：

```bash
./scripts/build_pyinstaller.sh
```

脚本会清理旧的 `dist/`、`build/`、`flux.spec`，然后生成单文件可执行产物 `dist/flux-xdr`。

## 8. 项目结构

```text
backend/
  app/
    api/          FastAPI 路由层
    services/     对话、配置、统计等服务
    skills/       Copilot 技能实现
    playbook/     Playbook 模板与参数校验
    workflow/     Workflow 引擎、调度与服务
    pipeline/     IR、Lint、Safety Gate
    models/       Pydantic/SQLModel 模型
    tests/        单元测试
frontend/
  index.html      页面入口
  app.js          工作台逻辑、设置面板、Playbook UI
  styles.css      样式
scripts/
  run_dev.sh
  migrate_db.py
  build_pyinstaller.sh
docs/
  api-ref/        上游接口原始文档
  skill-api-matrix-spec.md
```

## 9. 补充文档

- [User_Manual.md](User_Manual.md)：面向使用者的详细操作手册
- [docs/api-ref](docs/api-ref)：上游 XDR 接口原始资料
- [docs/skill-api-matrix-spec.md](docs/skill-api-matrix-spec.md)：Skill 与 API 对照、缺参追问、安全策略
- [PRD.md](PRD.md)：需求背景与产品定位

说明：

- `README` 负责高密度总览、接口/统计口径和研发落地入口
- `User_Manual.md` 继续承担详细操作步骤和场景化使用说明

## 10. Git 忽略与仓库整理建议

当前 `.gitignore` 已补充运行数据库、打包产物、本地环境文件与缓存规则。需要注意的是，以下文件目前已经被 Git 跟踪，单纯增加 `.gitignore` 不会自动停止跟踪：

- `flux.db`
- `data/flux.db`
- `data/test_flux.db`
- `flux2-flux.tar`

建议后续单独安排一次仓库整理，把这些运行/交付产物从索引中移除，再继续依赖 `.gitignore` 维持本地工作流。
