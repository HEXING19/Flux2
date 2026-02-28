# Flux Playbook 场景化能力实施计划（编码前）

## 0. 目标与边界

### 0.1 目标
- 在现有 Flux 能力基础上，新增可一键触发的内置自动化场景（Playbook）。
- 场景覆盖：
  - 场景一：一键“早巡”与安全大盘播报（Routine Check）
  - 场景二：单点告警“一键深度研判”（Alert Triage）
  - 场景三：特定攻击者“追踪溯源”（Threat Hunting）
- 在前端新增“场景百宝箱（Playbook Hub）”和“渐进式下一步动作（Progressive Disclosure）”。

### 0.2 本轮确认约束（已冻结）
- 场景二/三在 V1 阶段，接受“日志计数统计”替代“日志明细列表”。
- 场景三默认追溯窗口：90 天；默认扫描上限：2000 条事件。
- 前端一键按钮采用“直接调用 Playbook API”，不走自然语言中转。

### 0.3 非目标（本轮不做）
- 不新增真实“网络安全日志明细列表”接口对接（因当前 API 文档中未提供对应明细接口）。
- 不改造已有危险动作审批主链路（EventAction/BlockAction 既有机制保持）。
- 不替换当前 Intent/Skill 框架，仅在其上扩展 Playbook 编排层。

---

## 1. 当前可复用能力盘点

## 1.1 已跑通的 4 个核心接口
- `POST /api/xdr/v1/incidents/list`
  - 用途：查询事件列表（支持 `startTimestamp/endTimestamp/severities/dealStatus/page/pageSize/sort`）。
- `GET /api/xdr/v1/incidents/{uuid}/proof`
  - 用途：获取事件举证、时间线、风险标签、AI 研判字段等。
- `GET /api/xdr/v1/incidents/{uuid}/entities/ip`
  - 用途：获取事件关联外网实体 IP、地理、标签、处置建议等。
- `POST /api/xdr/v1/analysislog/networksecurity/count`
  - 用途：网络安全日志计数（支持 `srcIps/dstIps/severities/attackStates/productTypes` 等过滤）。

## 1.2 现有可复用模块
- DAG 引擎：`backend/app/workflow/engine.py`（支持依赖与并发执行）。
- Skill 能力：`event_query/event_detail/entity_query/log_stats` 已具备可复用请求封装。
- LLM 路由：`backend/app/llm/router.py` 可直接用于总结阶段。
- 前端卡片渲染：已有 `text/table/echarts_graph/approval_card/form_card`。

---

## 2. 总体架构设计（新增）

## 2.1 新增抽象：Playbook Runtime
- 新增 `PlaybookService`（建议目录：`backend/app/playbook/`）：
  - 负责场景注册、入参校验、DAG 组装、执行、状态持久化、结果输出标准化。
- 新增 `PlaybookRegistry`：
  - 内置 3 个模板：`routine_check`、`alert_triage`、`threat_hunting`。
- 新增 `PlaybookRun` 数据模型（建议写入 DB）：
  - 字段：`id/template/status/input_json/context_json/result_json/error/started_at/finished_at/created_by`。

## 2.2 API 设计（后端）
- `GET /api/playbooks/templates`
  - 返回可展示的场景模板元数据（名称、描述、需要参数、默认参数、推荐按钮文案）。
- `POST /api/playbooks/run`
  - 输入：`template_id + params + session_id(optional)`
  - 输出：`run_id + status + partial_context`
- `GET /api/playbooks/runs/{run_id}`
  - 返回：完整执行结果、节点状态、输出卡片、`next_actions`。

## 2.3 输出协议统一（前后端契约）
- 统一返回结构（建议）：
  - `summary`: 结构化文本摘要
  - `cards`: payload 数组（兼容现有 `text/table/echarts_graph`）
  - `next_actions`: 下一步动作数组（按钮渲染源）
- `next_actions` 单项建议：
  - `id`, `label`, `template_id`, `params`, `style`（primary/secondary/danger）

---

## 3. 场景一：Routine Check（今日安全早报）

## 3.1 触发方式
- 前端 Playbook Hub 按钮：`☕ 生成今日安全早报`
- API：`POST /api/playbooks/run`，`template_id="routine_check"`

## 3.2 DAG 设计
- `node_1_log_count_24h`
  - 接口：`POST /api/xdr/v1/analysislog/networksecurity/count`
  - 入参：
    - `startTimestamp=now-24h`
    - `endTimestamp=now`
  - 产出：`log_total_24h`
- `node_2_unhandled_high_events_24h`
  - 接口：`POST /api/xdr/v1/incidents/list`
  - 入参：
    - `startTimestamp=now-24h`
    - `endTimestamp=now`
    - `dealStatus=[0]`
    - `severities=[3,4]`
    - `page=1,pageSize=50,sort=endTime:desc,severity:desc`
  - 产出：`high_events[]`
- `node_3_sample_detail_parallel`（可选）
  - 对前 N 条（默认 N=3）并发调用：
    - `GET /api/xdr/v1/incidents/{uuid}/proof`
    - `GET /api/xdr/v1/incidents/{uuid}/entities/ip`
  - 产出：`sample_evidence[]`
- `node_4_llm_briefing`
  - 输入：`log_total_24h + high_events + sample_evidence`
  - 输出：晨报文案（固定结构：总体态势/关键风险/建议动作）

## 3.3 返回卡片建议
- 文本卡：今日早报结论。
- 图表卡：24h 总量与趋势（V1 可沿用现有伪趋势生成方式，后续替换真实分段统计）。
- 表格卡：未处置高危事件列表。
- 下一步动作：
  - “🔍 一键深度研判前3条事件”
  - “🕵️ 生成首个源 IP 的活动轨迹”

---

## 4. 场景二：Alert Triage（单点告警深度研判）

## 4.1 触发方式
- 从事件表卡片或详情卡片触发“🔍 一键深度研判”。
- API：`POST /api/playbooks/run`，`template_id="alert_triage"`。
- 输入参数：
  - `incident_uuid`（优先）
  - 或 `event_index` + `session_id`（通过上下文索引转换为 uuid）

## 4.2 DAG 设计
- `node_1_resolve_target`
  - 输入解析：`incident_uuid` / `event_index`。
  - 若 index 模式：复用 `context_manager.resolve_indices(..., "events", ...)`。
- `node_2_entity_profile`
  - 接口：`GET /api/xdr/v1/incidents/{uuid}/entities/ip`
  - 产出：候选 IP、威胁标签、地域、处置建议。
- `node_3_external_intel`
  - 调用 ThreatBook（若有 Key）或本地启发式回退。
  - 产出：`reputation/severity/confidence/tags`。
- `node_4_internal_impact_count_parallel`（V1 计数版）
  - 接口：`POST /api/xdr/v1/analysislog/networksecurity/count`
  - 对每个目标 IP 并发计算：
    - 总访问量：`srcIps=[ip]`
    - 高危访问量：`srcIps=[ip],severities=[3,4]`
    - 成功/失陷量：`srcIps=[ip],attackStates=[2,3]`
    - 时间范围：默认 `now-7d -> now`
  - 产出：`blast_radius_score` 相关计数。
- `node_5_llm_triage_summary`
  - 输入：实体画像 + 外情报 + 内部计数
  - 输出：
    - 攻击真实性概率（文字化区间）
    - 关键证据
    - 优先建议动作（封禁/观察/人工复核）

## 4.3 返回卡片建议
- 文本卡：研判结论（含“建议立即封禁/建议继续观察”）。
- 表格卡：目标 IP 的计数对比（总量/高危/成功失陷）。
- 表格卡：实体情报明细（severity/tags/confidence）。
- 下一步动作：
  - “封禁该 IP（进入审批）”
  - “生成该 IP 90 天活动轨迹”

---

## 5. 场景三：Threat Hunting（攻击者活动轨迹）

## 5.1 触发方式
- Playbook Hub 按钮：`🕵️ 攻击者活动轨迹生成`
- API：`POST /api/playbooks/run`，`template_id="threat_hunting"`
- 输入参数：
  - 必填：`ip`
  - 可选：`startTimestamp/endTimestamp`
  - 默认：`90 天窗口`

## 5.2 DAG 设计
- `node_1_external_profile`
  - ThreatBook 画像（团伙背景、信誉、标签）。
- `node_2_event_scan_paginated`
  - 接口：`POST /api/xdr/v1/incidents/list`
  - 扫描策略：
    - 时间窗默认 90 天
    - `pageSize=200`
    - 最多扫描 2000 条（10 页）
  - 本地过滤：
    - `hostIp == target_ip`
    - 或 `description` 文本包含 `target_ip`
  - 产出：命中事件列表（按时间倒序）
- `node_3_evidence_enrichment_parallel`
  - 对命中事件（建议上限 20）并发：
    - `GET /api/xdr/v1/incidents/{uuid}/proof`
    - `GET /api/xdr/v1/incidents/{uuid}/entities/ip`
  - 产出：事件节点证据。
- `node_4_internal_activity_count`
  - 接口：`POST /api/xdr/v1/analysislog/networksecurity/count`
  - 统计：
    - `srcIps=[ip]`、`dstIps=[ip]`
    - 7/30/90 天对比（可并发）
- `node_5_llm_timeline_story`
  - 输出按时间线组织的“攻击故事线”：
    - 侦察 -> 利用 -> 横向 -> 结果
    - 每一段附关键证据。

## 5.3 返回卡片建议
- 文本卡：轨迹结论与风险等级。
- 表格卡：命中事件清单（时间、事件名、等级、状态）。
- 文本卡：时间线叙事（适合汇报复制）。
- 下一步动作：
  - “导出溯源摘要”
  - “对高风险节点执行处置审批”

---

## 6. 前端改造计划

## 6.1 Playbook Hub（首页场景百宝箱）
- 位置：Copilot 主工作区顶部，输入框上方。
- 默认卡片：
  - 今日安全早报
  - 一键深度研判（需先选事件）
  - 攻击者活动轨迹
- 行为：点击后直接调用 `POST /api/playbooks/run`，并轮询 `GET /api/playbooks/runs/{id}` 或长轮询刷新结果。

## 6.2 Progressive Disclosure（结果后续引导）
- 在每个 Playbook 结果末尾渲染 `next_actions` 按钮行。
- 点击下一步动作时：
  - 直接触发下一个 Playbook API（带透传参数）。
- 场景串联示例：
  - 早报 -> 深度研判前3条
  - 深度研判 -> 轨迹生成 -> 封禁审批

## 6.3 兼容性与交互细节
- 不破坏现有 chat SSE 链路；Playbook 区块作为并行入口。
- 对运行中状态提供节点进度显示（pending/running/finished/failed）。
- 出错展示“节点级错误”而非仅全局错误。

---

## 7. 后端详细改造清单（仅计划）

## 7.1 新增目录与文件（建议）
- `backend/app/playbook/__init__.py`
- `backend/app/playbook/registry.py`
- `backend/app/playbook/schemas.py`
- `backend/app/playbook/service.py`
- `backend/app/api/routes_playbook.py`

## 7.2 复用与扩展点
- 复用 `WorkflowEngine` 作为 DAG 运行内核。
- 复用 `SkillRegistry` 已有 Skill，避免重复实现请求逻辑。
- 复用 `LLMRouter` 生成总结结果。
- 必要时在 `log_stats_skill` 增加可选“只返回 total 不画图”分支，供场景节点调用。

## 7.3 现有文件改造（建议）
- `backend/app/main.py`
  - 挂载 `routes_playbook`。
- `backend/app/models/db_models.py`
  - 新增 `PlaybookRun`（若采用持久化方式）。
- `backend/app/core/payload.py`
  - 新增 `next_actions` 相关 payload（可选）。
- `backend/app/services/chat_service.py`
  - 可选：为聊天上下文写入 Playbook 结果索引，支撑“第N条事件”后续对话。

---

## 8. 测试计划

## 8.1 单元测试
- Playbook 参数校验：
  - 场景二缺失 `incident_uuid/event_index` -> 正确报错。
  - 场景三缺失 `ip` -> 正确报错。
- 场景二计数逻辑：
  - `srcIps+severities/attackStates` 请求体构造正确。
- 场景三扫描上限：
  - 超过 2000 条后停止扫描。

## 8.2 集成测试（Mock requester）
- `routine_check` 完整执行并返回卡片+next_actions。
- `alert_triage` 完整执行并返回计数证据链。
- `threat_hunting` 在 90 天窗口内生成时间线文本。

## 8.3 前端联调测试
- Playbook Hub 按钮触发 API 成功。
- 运行态与失败态渲染正常。
- `next_actions` 可串联触发下游场景。

---

## 9. 验收标准（Definition of Done）

## 9.1 功能验收
- 三个场景可从前端一键触发并稳定返回结果。
- 返回结果至少包含：摘要、关键证据卡片、下一步动作。
- 场景二/三已使用“日志计数统计”完成内部影响评估。

## 9.2 性能与稳定性
- 单场景平均响应目标：10 秒内（依赖外部 LLM/情报 API 时可延长并给出进度）。
- 关键节点失败可降级：例如 ThreatBook 不可用时使用本地评估并继续。

## 9.3 安全与审计
- 不新增绕过审批的危险动作通道。
- 场景产物中应保留证据来源字段（接口名/时间窗/关键参数）。

---

## 10. 风险与缓解

## 10.1 风险
- 无日志明细接口导致“渗透路径细节”表达粒度受限。
- 事件列表不支持直接按 IP 精确检索，场景三依赖分页扫描，可能耗时波动。
- 外部情报服务（ThreatBook）可能限流或不可用。

## 10.2 缓解
- 先用计数指标建立稳定“风险强弱判断”。
- 场景三严格限制窗口和扫描上限，保障可预测时延。
- 外情报失败自动回退到本地启发式评估，确保流程不中断。

---

## 11. 里程碑与交付顺序（编码阶段将按此执行）

1. M1：Playbook API 与运行骨架（模板查询、运行、结果查询）。
2. M2：场景一（早巡）全链路打通。
3. M3：场景二（深度研判）全链路打通。
4. M4：场景三（追踪溯源）全链路打通。
5. M5：前端 Playbook Hub 与 Progressive Disclosure 上线。
6. M6：测试补齐与验收修复。

---

## 12. 备注
- 本文档为“编码前执行蓝图”，当前仅完成计划沉淀，不包含任何功能代码实现。
