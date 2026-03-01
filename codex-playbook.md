# Playbook Hub 任务实现路径拆解

日期：2026-03-01  
范围：`Playbook Hub` 场景扩展、执行进度可视化、单点研判交互修复、微步 API Key 管理设置补齐

## 0. 目标与现状确认

### 目标
1. 新增“核心资产防线透视（Asset-Centric Guard）”场景，支持围绕核心资产（IP）做态势体检与管理层汇报。
2. 修复“生成今日安全早报”运行失败（`error: 'nodes'`），并把运行进度改造成用户可读、阶段化、可视化的任务状态展示；并检查其他场景同类问题。
3. 修复“一键深度研判”触发信息不展示事件 ID 的问题；将结果改成单个主卡片（一个大 `div` 内含多个小分区）而不是多个并列卡片。
4. 在“管理设置”补齐微步（ThreatBook）API Key 配置能力，并打通到现有实体情报/Playbook 调用链路。

### 现状关键问题（已定位）
1. `routine_check` DAG 中 `node_2_unhandled_high_events_24h` 实际读取 `ctx["nodes"]["node_1_log_count_24h"]`，但依赖未声明，导致并行执行时 `ctx["nodes"]` 尚未建立，触发 `KeyError: 'nodes'`。
2. 进度展示当前是纯文本 `pre`，节点名直接暴露技术 ID，不利于用户理解。
3. `alert_triage` 触发信息只显示场景名，未拼接事件 ID；结果渲染存在重复总结与多卡片分散展示。
4. 系统有 `settings.threatbook_api_key` 使用逻辑，但管理设置无对应 UI/API 持久化配置入口。

## 1. 实施顺序（推荐）

1. 先修稳定性：修复 `routine_check` DAG 依赖错误，补测试，确保 Playbook 基本可跑通。  
2. 再做统一进度可视化：抽象节点展示元数据，覆盖全部 Playbook 场景。  
3. 再做 `alert_triage` 交互与结果卡片改造：触发文案 + 单卡片聚合。  
4. 最后新增 `Asset-Centric Guard` 场景与核心资产管理设置。  
5. 最后补 ThreatBook 配置页与后端存取，并联调实体情报调用链。  

## 2. 任务一：新增“核心资产防线透视（Asset-Centric Guard）”

## 2.1 产品与数据建模

### 核心资产维护方案（推荐）
新增独立配置实体，不与 Safety Gate 规则强耦合：
- 新表：`CoreAsset`
  - `id`
  - `asset_name`（如“核心交易库”）
  - `asset_ip`
  - `biz_owner`（可选）
  - `metadata`（可选，JSON 文本）
  - `created_at` / `updated_at`

说明：  
- 保留与“高危防线与红线”`description` 的软关联能力（如匹配同 IP 时复用备注），但不依赖其结构化语义。  
- 这样不会污染安全拦截规则语义，也便于后续扩展资产分组、业务系统标签。

### 设置页改造
管理设置新增 `核心资产管理` Tab：
- 列表：资产名、IP、负责人、备注。
- 新增/删除资产。
- 支持从“高危防线”已存在 IP 快速导入（可选增强）。

## 2.2 Playbook 场景接入

### 后端改造点
1. `backend/app/playbook/schemas.py`
- `PlaybookRunRequest.template_id` 增加 `"asset_guard"`。

2. `backend/app/playbook/registry.py`
- 增加模板：
  - `id`: `asset_guard`
  - `name`: 核心资产防线透视
  - `button_label`: `🏥 核心资产一键体检`
  - `default_params`: `window_hours=24`, `top_external_ip=5`
  - 参数：`asset_ip`、`asset_name`（可选）、`window_hours`、`top_external_ip`

3. `backend/app/playbook/service.py`
- `_normalize_params` 新增 `asset_guard` 归一化。
- `_validate_input` 新增 `asset_ip` 校验（IP 格式、必填）。
- `_initial_node_status` 新增资产场景节点定义。
- 新增 `_build_asset_guard(runtime_context)`。

### DAG 设计（按你的需求拆解）
1. `node_1_events_dst_asset`
- 以核心资产 IP 为目的维度统计/拉取相关告警。

2. `node_2_events_src_asset`
- 以核心资产 IP 为源维度统计/拉取相关告警。

3. `node_3_logs_dst_asset`
- 查询（或计数）资产作为目的 IP 的访问行为。

4. `node_4_logs_src_asset`
- 查询（或计数）资产作为源 IP 的访问行为。

5. `node_5_top_external_ip`
- 汇总外部 IP 访问量，提取 Top 5（需定义“外部”口径：非 RFC1918/非本地白名单）。

6. `node_6_external_intel_enrich`
- 对 Top 5 外部 IP 执行 ThreatBook/本地降级画像。

7. `node_7_llm_asset_briefing`
- 输出管理层语言总结（总体态势、隐患、建议动作）。

### 返回卡片建议
- 卡片1：`核心资产态势结论`
- 卡片2：`资产双向告警统计`（src/dst）
- 卡片3：`Top 5 外部访问实体情报`
- 卡片4（可选）：`建议动作`（深度研判、封禁审批、轨迹分析）

### 前端接入点
1. `frontend/app.js`
- `DEFAULT_PLAYBOOK_SCENES` 增加 `asset_guard`。
- `buildSceneParams` 增加资产 IP/资产名输入逻辑（优先输入 IP）。

2. `frontend/index.html`
- 设置页新增 `核心资产管理` Tab 容器。

3. `frontend/styles.css`
- 为新 Tab 与资产列表/表单补样式。

## 2.3 验收标准
- 点击“🏥 核心资产一键体检”后可成功执行，输出资产视角总结。
- 文案体现“保护对象中心”而非攻击者中心。
- 可从管理设置维护资产，场景输入支持复用。

## 3. 任务二：进度展示优化 + `routine_check` 失败修复

## 3.1 故障修复（必须先做）

### 根因
`backend/app/playbook/service.py` 中 `routine_check` 的 `node_2_unhandled_high_events_24h` 使用了 `node_1` 结果，但在 DAG 定义里没有 `depends_on`，导致两节点并行启动时出现 `ctx["nodes"]` 缺失。

### 修复方案
1. 在 `_build_routine_check` 的节点定义中：
- `node_2_unhandled_high_events_24h` 增加 `depends_on=["node_1_log_count_24h"]`。

2. 在 `_initial_node_status` 中同步修正依赖关系：
- `node_2_unhandled_high_events_24h` 的 `depends_on` 改为 `["node_1_log_count_24h"]`。

3. 回归检查其他场景依赖一致性：
- `alert_triage`、`alert_triage(block_ip)`、`threat_hunting` 当前依赖关系与读取逻辑一致，无同类问题。

### 防回归建议
- 新增测试：断言 `routine_check` 可稳定 `Finished`，且不出现 `error: 'nodes'`。
- 可选新增“节点读取依赖校验”单元测试（扫描 `ctx["nodes"]["xxx"]` 与 `depends_on` 映射一致性）。

## 3.2 进度视觉与用户语言改造

### 目标
把当前技术日志式文本：
- `node_xxx`
- `Running/Failed/Pending`
改造成阶段化流程视图，用户可快速理解“当前在做什么、做到哪一步、为什么失败”。

### 前端实现路径
1. `frontend/app.js`
- 增加 `PLAYBOOK_STAGE_META` 映射：
  - 按 `template_id + mode` 维护每个节点的用户语言标题、说明、阶段顺序。
- 改造 `createPlaybookProgressCard`：
  - 保留标题与 run_id
  - 增加阶段列表容器（非仅 `pre`）
  - 增加整体进度条/百分比
- 改造 `updatePlaybookProgress`：
  - 状态文案映射：`Pending/Running/Finished/Failed` -> `等待中/执行中/已完成/失败`
  - 失败节点展示简化原因（保留原错误在“技术详情”折叠区）
  - 未知节点 fallback 为“后台任务”

2. `frontend/styles.css`
- 新增阶段卡样式：
  - 状态徽标（等待/执行中/完成/失败）
  - 进度条
  - 当前步骤高亮
- 保持移动端可读性（单列布局）。

### 后端可选增强（建议）
- 在 `node_status` 中补充 `label`/`desc` 字段，避免前后端映射漂移。

## 3.3 验收标准
- “生成今日安全早报”不再失败于 `node_2`，可完整跑完。
- 进度展示不再直接暴露 `node_xxx` 给业务用户；能清晰看到当前阶段和总进度。
- 其他 Playbook 场景（`alert_triage`、`threat_hunting`）进度视图风格一致。

## 4. 任务三：一键深度研判触发信息与结果卡片聚合

## 4.1 触发信息展示事件ID

### 现状
`frontend/app.js` -> `runPlaybook` 固定写入：
- `触发场景: ${triggerLabel || templateId}`
未拼接具体事件 ID/序号。

### 修复路径
1. 新增辅助函数 `formatTriggerLabel(templateId, triggerLabel, params)`：
- `alert_triage` 下优先展示：
  - `incident_uuid`
  - `incident_uuids`（多条时可显示前1条+数量）
  - `event_index/event_indexes`（回退）
- 输出：`触发场景: 单点告警深度研判（incident-xxx）`

2. `runPlaybook` 调用该函数替换原始文案。

## 4.2 结果改为“单主卡 + 多子区块”

### 现状问题
当前会渲染：
- `Playbook 结果 · alert_triage`（summary）
- `单点告警深度研判结论`（同内容）
- 多个表格卡片  
导致重复且分散。

### 修复策略（推荐前端聚合，不改后端结构）
1. 在 `renderPlaybookResult` 中新增 `alert_triage` 专用渲染分支。
2. 新函数 `renderAlertTriageUnifiedCard(runData)`：
- 只创建一个主 `chat-card`
- 内含多个子 `div`（例如：结论、关键证据、内部影响、外部情报、实体画像）
- 复用已有 `result.cards` 数据组装子区块

3. 处理 summary 重复
- 通用去重规则：若 `result.cards` 首个文本卡的 `text` 与 `result.summary` 一致，则不再额外渲染 summary 卡。
- 对其他场景一起生效，避免同类重复。

### 样式改造
`frontend/styles.css` 新增：
- `playbook-unified-report`
- `report-section`
- `report-section-title`

## 4.3 验收标准
- 触发后用户卡片展示：`触发场景: 单点告警深度研判（事件ID）`。
- 研判结果仅一个主卡片，内部按区块展示；不再出现两个内容重复卡片。

## 5. 任务四：管理设置补齐 ThreatBook API Key 配置

## 5.1 后端设计

### 存储方案（推荐）
新增独立配置模型，避免与 LLM Provider 混用：
- `ThreatIntelConfig`
  - `id`
  - `provider`（固定 `threatbook`）
  - `api_key`
  - `enabled`
  - `updated_at`

### API
在 `backend/app/api/routes_config.py` 增加：
1. `GET /api/config/threatbook`
- 返回 `enabled`、`has_key`、`masked_key`、`updated_at`

2. `POST /api/config/threatbook`
- 入参：`api_key`、`enabled`
- 持久化更新

3. （可选）`POST /api/config/threatbook/test`
- 使用输入 key 调用一次 `ip_reputation` 做连通性校验（可选）

### 调用链路接入
1. `backend/app/playbook/service.py::_query_intel`
- key 读取顺序：DB 配置 > `settings.threatbook_api_key`（环境变量兜底）

2. `backend/app/skills/entity_skill.py::_query_threatbook`
- 同步改为 DB+env 双来源读取，避免“设置页配置了但技能读不到”。

## 5.2 前端设置页改造

1. `frontend/index.html`
- 设置页新增 `威胁情报联动` Tab（或挂在 LLM Tab 下独立块）。
- 字段：`ThreatBook API Key`、启用开关、保存按钮、连通性测试按钮（可选）。

2. `frontend/app.js`
- 新增 `loadThreatbookConfig()`、`saveThreatbookConfig()`、`testThreatbookConfig()`。
- 打开设置弹窗时联动加载。

3. `frontend/styles.css`
- 复用现有 settings form 样式，补最少增量类名。

## 5.3 验收标准
- 管理设置可查看并更新 ThreatBook Key。
- 配置后，实体情报查询文案从“未检测到微步Key，已返回本地评估结果”切换为真实 ThreatBook 查询结果（在网络可达时）。

## 6. 回归测试清单

## 6.1 后端
1. `routine_check` 运行成功，不再出现 `error: 'nodes'`。
2. `alert_triage`（incident_uuid / event_index）均可运行。
3. `threat_hunting` 运行正常。
4. `asset_guard` 新场景参数校验、流程执行、结果结构正确。
5. ThreatBook 配置 API 增删改查正常，配置可被 playbook 与 entity skill 读取。

## 6.2 前端
1. 所有 Playbook 进度卡展示为阶段化视图，状态转换正常。
2. 一键深度研判触发文案带事件 ID。
3. `alert_triage` 结果为单主卡片，不重复展示 summary。
4. 管理设置新增 Tab 可打开、保存、刷新并保持状态。

## 7. 风险与注意事项

1. XDR 日志“Top5 外部 IP”依赖日志明细接口能力；若当前平台仅提供 count，可先做“基于事件实体聚合”的 MVP，再升级为日志明细统计。
2. ThreatBook key 建议后端返回掩码而非明文，避免前端泄漏。
3. 新增表结构后需确保 `init_db()` 在已有库上可平滑 `create_all`。
4. `PlaybookRunRequest.template_id` 扩展后，前端默认场景与后端模板列表需一致。

## 8. 交付拆分建议（两次迭代）

### 迭代A（稳定性+体验修复）
1. 修 `routine_check` DAG 依赖 bug。  
2. 全场景进度可视化改造。  
3. `alert_triage` 触发文案 + 单卡片展示 + 去重。  
4. ThreatBook 设置页与 API 打通。  

### 迭代B（能力新增）
1. 核心资产管理 Tab。  
2. `asset_guard` Playbook 场景全链路上线。  
3. 与高危防线 Metadata 的关联增强（导入/联动）。  

