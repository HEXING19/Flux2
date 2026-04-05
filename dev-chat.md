# 安全运营对话分析能力开发任务清单

## 1. 目标

本轮开发目标是在现有 Flux 对话框架上新增 5 类安全运营分析问答能力，并保持现有聊天协议不变：

1. 安全事件发生趋势
2. 安全事件类型分布
3. 安全事件处置成果
4. 重点安全事件解读
5. 安全告警分类情况

要求用户可以直接通过自然语言提问，例如：

- 帮我统计最近 7 天的安全事件发生趋势
- 最近 7 天安全事件类型分布
- 最近 7 天安全事件处置成果
- 重点安全事件解读
- 最近 7 天安全告警分类情况

## 2. 本轮实现边界

### 2.1 可以实现的部分

- 基于 `incidents/list` 实现事件趋势、事件类型分布、事件处置快照、重点事件筛选
- 基于 `incidents/{uuid}/proof` 与 `incidents/{uuid}/entities/ip` 实现重点事件深度解读
- 基于 `alerts/list` 实现告警分类情况、告警严重性分布、告警处置状态分布、访问方向分布
- 保持返回格式为 `text/table/echarts_graph`，无需改动聊天接口协议

### 2.2 不能完整实现的部分

- “安全事件处置成果”只能先做“当前状态快照版”
- 不能精确实现“最近 7 天完成处置数量变化”“平均处置耗时”“状态流转历史轨迹”
- 原因：当前外部事件接口未明确提供事件处置历史、处置完成时间、状态变更流水

### 2.3 本轮建议口径

- 事件趋势：默认按天聚合；当时间窗口不超过 48 小时时，自动按小时聚合
- 事件类型分布：默认按 `threatDefineName` 展示；补充 `incidentThreatClass/incidentThreatType` 编码
- 事件处置成果：按当前查询窗口内事件的当前 `dealStatus`、`dealAction` 聚合
- 重点事件解读：默认挑选 Top 3，排序优先级为“严重度 > 未处置 > 最近发生时间”
- 告警分类情况：默认按 `threatClassDesc / threatTypeDesc / threatSubTypeDesc` 展示 TopN

## 3. 每项需求的输出内容定义

### 3.1 安全事件发生趋势

输出至少包含：

- 查询时间范围
- 事件总数
- 总体趋势图
- 按等级拆分的趋势图或堆叠图
- 峰值日期/时段
- 趋势明细表

### 3.2 安全事件类型分布

输出至少包含：

- 查询时间范围
- 事件总数
- 按威胁定性分布 TopN
- 按事件一级/二级分类分布
- 高危/严重事件类型 TopN
- 分布明细表

### 3.3 安全事件处置成果

输出至少包含：

- 查询时间范围
- 事件总数
- 各处置状态数量与占比
- 已处置率
- 处置动作分布
- 待处置重点事件清单
- 说明“当前版本为状态快照，不含历史处置流水”

### 3.4 重点安全事件解读

输出至少包含：

- 重点事件列表
- 每条重点事件的名称、等级、状态、最近发生时间
- GPT 研判结论
- 风险标签
- 关键时间线摘要
- 关联外网实体
- 建议处置动作

### 3.5 安全告警分类情况

输出至少包含：

- 查询时间范围
- 告警总数
- 告警一级分类 TopN
- 告警二级分类 TopN
- 告警三级分类 TopN
- 告警严重性分布
- 告警处置状态分布
- 访问方向分布
- 明细表

## 4. 文件级开发任务清单

---

## 4.1 新增文件

### A. `backend/app/services/security_analytics_service.py`

职责：新增统一的“安全分析聚合服务”，沉淀所有统计、分页扫描、聚合和排序逻辑，避免 skill 内部堆满业务代码。

开发任务：

- 封装事件查询分页能力
- 封装告警查询分页能力
- 统一时间桶生成逻辑
- 统一事件/告警行数据标准化逻辑
- 实现趋势聚合函数
- 实现类型分布聚合函数
- 实现处置成果聚合函数
- 实现重点事件排序函数
- 实现告警分类聚合函数
- 输出结构中带上 `truncated/max_scan/total_hint`，便于前端和文案提示

建议函数拆分：

- `query_incidents(...)`
- `scan_incidents(...)`
- `query_alerts(...)`
- `scan_alerts(...)`
- `build_time_buckets(...)`
- `aggregate_event_trend(...)`
- `aggregate_event_type_distribution(...)`
- `aggregate_event_disposition_summary(...)`
- `select_key_events(...)`
- `build_key_event_insight(...)`
- `aggregate_alert_classification_summary(...)`

实现细节：

- 复用现有 playbook 中的分页扫描逻辑
- 复用现有事件/告警 normalize 逻辑
- 支持最大扫描量限制，默认建议 `10000`
- 对分布类统计按数量降序排序，取 TopN，剩余归类为“其他”
- 对趋势类统计支持 `day/hour` 两种粒度

验收标准：

- 同一统计逻辑可被多个 skill 复用
- 空数据、字段缺失、接口失败场景可稳定返回
- 返回结果包含用于文案渲染的统计摘要数据

---

### B. `backend/app/skills/security_analytics_skills.py`

职责：新增 5 个对话分析 skill，负责参数校验、调用分析服务、组装 payload。

开发任务：

- 定义统一输入模型 `SecurityAnalyticsBaseInput`
- 定义 `EventTrendSkill`
- 定义 `EventTypeDistributionSkill`
- 定义 `EventDispositionSummarySkill`
- 定义 `KeyEventInsightSkill`
- 定义 `AlertClassificationSummarySkill`

每个 skill 的输出建议：

- `EventTrendSkill`
  - `text_payload`：总结趋势、峰值、等级变化
  - `echarts_payload`：总趋势图
  - `echarts_payload`：按等级堆叠趋势图
  - `table_payload`：趋势明细表

- `EventTypeDistributionSkill`
  - `text_payload`：分布摘要
  - `echarts_payload`：TopN 柱状图或饼图
  - `table_payload`：类型分布明细

- `EventDispositionSummarySkill`
  - `text_payload`：处置成果摘要
  - `echarts_payload`：状态分布图
  - `echarts_payload`：处置动作分布图
  - `table_payload`：状态/动作明细表
  - `table_payload`：待处置重点事件表

- `KeyEventInsightSkill`
  - `text_payload`：总体摘要
  - `table_payload`：重点事件总表
  - `text_payload`：逐条事件解读
  - `table_payload`：必要时输出时间线表

- `AlertClassificationSummarySkill`
  - `text_payload`：告警分类摘要
  - `echarts_payload`：一级分类分布
  - `echarts_payload`：二级或三级分类分布
  - `echarts_payload`：严重性/处置状态分布
  - `table_payload`：分类明细表

实现细节：

- 所有 skill 都应支持 `time_text`
- `KeyEventInsightSkill` 支持默认 Top3，可通过 `page_size` 或 `top_n` 调整
- 处置成果 skill 的文案中必须明确“当前为状态快照，不代表历史处置流水”
- 若扫描被截断，摘要文案中必须明确提示

验收标准：

- 5 个 skill 均能独立执行
- 输出 payload 能被现有前端直接渲染
- 无需新增前端 payload 类型

---

### C. `backend/app/tests/test_security_analytics_service.py`

职责：覆盖聚合服务的纯逻辑测试。

开发任务：

- 为事件趋势聚合写测试
- 为事件类型分布写测试
- 为事件处置成果写测试
- 为告警分类情况写测试
- 为 TopN 与“其他”合并逻辑写测试
- 为 `truncated` 提示写测试
- 为小时/天粒度切换写测试

建议测试场景：

- 最近 7 天按天聚合
- 最近 24 小时按小时聚合
- 多等级事件混合统计
- 空结果统计
- 分类字段缺失时的回退行为
- 超过 `max_scan` 的截断行为

---

### D. `backend/app/tests/test_security_analytics_skills.py`

职责：覆盖 5 个新 skill 的端到端输出结构测试。

开发任务：

- 为 5 个 skill 准备 FakeRequester
- 校验返回 payload 顺序和类型
- 校验摘要文本包含核心统计值
- 校验图表 option 结构完整
- 校验明细表字段齐全
- 校验异常场景下返回友好文本

---

## 4.2 修改文件

### E. `backend/app/skills/registry.py`

职责：注册新增分析 skill。

开发任务：

- 引入 `security_analytics_skills.py`
- 注册以下 intent
  - `event_trend`
  - `event_type_distribution`
  - `event_disposition_summary`
  - `key_event_insight`
  - `alert_classification_summary`

验收标准：

- `supported_intents()` 返回新增 intent
- 新增 skill 可以被 pipeline 正常获取

---

### F. `backend/app/services/intent_parser.py`

职责：把用户自然语言准确路由到新增 intent。

开发任务：

- 增加“趋势类”识别规则
- 增加“类型分布类”识别规则
- 增加“处置成果类”识别规则
- 增加“重点解读类”识别规则
- 增加“告警分类情况类”识别规则
- 避免把“告警分类情况”误判为普通 `event_query`

建议新增关键词：

- `event_trend`
  - 趋势
  - 发生趋势
  - 态势趋势
  - 每天多少事件

- `event_type_distribution`
  - 类型分布
  - 事件分布
  - 威胁类型分布
  - 事件分类分布

- `event_disposition_summary`
  - 处置成果
  - 处置情况
  - 处置效果
  - 处置统计

- `key_event_insight`
  - 重点事件解读
  - 重点安全事件
  - 重点事件分析
  - 帮我解读重点事件

- `alert_classification_summary`
  - 告警分类情况
  - 告警分类分布
  - 告警一级分类
  - 告警二级分类
  - 告警三级分类

同时补充参数提取：

- 时间范围 `time_text`
- 事件等级 `severities`
- 返回条数 `page_size`
- TopN 值

验收标准：

- 典型中文问法都能稳定路由
- 不影响现有事件查询、详情、处置逻辑

---

### G. `backend/app/core/semantic_rules.py`

职责：让新增 intent 能继续接入现有“语义规则配置”能力。

开发任务：

- 为新增 5 个 domain 增加 `SEMANTIC_RULE_META`
- 为每个 domain 配置允许的 slot
  - `time_text`
  - `severities`
  - `page_size`
  - 可选 `top_n`
  - 可选 `group_by`
- 配置可视化 label 和选项

建议新增 domain：

- `event_trend`
- `event_type_distribution`
- `event_disposition_summary`
- `key_event_insight`
- `alert_classification_summary`

验收标准：

- 配置页可正常创建对应语义规则
- 不会触发 `domain 不受支持`

---

### H. `backend/app/tests/test_intent_parser.py`

职责：补 intent 路由单测。

开发任务：

- 增加“最近 7 天安全事件发生趋势”应路由到 `event_trend`
- 增加“最近 7 天安全事件类型分布”应路由到 `event_type_distribution`
- 增加“最近 7 天安全事件处置成果”应路由到 `event_disposition_summary`
- 增加“重点安全事件解读”应路由到 `key_event_insight`
- 增加“最近 7 天安全告警分类情况”应路由到 `alert_classification_summary`
- 增加语义规则填槽测试

---

### I. `backend/app/tests/test_chat_confirm_flow.py`

职责：补聊天链路集成测试。

开发任务：

- 扩展 FakeRequester，支持 `/api/xdr/v1/alerts/list`
- 扩展 FakeRequester，支持更多事件字段
  - `threatDefineName`
  - `incidentThreatClass`
  - `incidentThreatType`
  - `gptResultDescription`
- 新增 5 个对话场景测试
  - 事件趋势
  - 类型分布
  - 处置成果
  - 重点事件解读
  - 告警分类情况

验收标准：

- 通过 `ChatService.handle()` 能完整拿到 payload
- 图表、表格、文本 payload 顺序稳定

---

### J. `docs/skill-api-matrix-spec.md`

职责：补文档，保持 skill 与 API 契约一致。

开发任务：

- 在 Skill-API Matrix 中补充 5 个新 skill
- 标清各自调用的外部 API
- 补自然语言示例
- 补缺参说明
- 明确“处置成果仅做状态快照”的限制

建议新增条目：

- `EventTrendSkill`
- `EventTypeDistributionSkill`
- `EventDispositionSummarySkill`
- `KeyEventInsightSkill`
- `AlertClassificationSummarySkill`

---

### K. `README.md`

职责：只做简短能力补充，不需要大改。

开发任务：

- 在功能列表中补一句“支持安全事件/告警统计分析问答”
- 如本轮未上线，可先不改

---

## 4.3 可选修改文件

### L. `frontend/app.js`

当前状态：现有前端已支持 `text/table/echarts_graph`，理论上本轮不是必须改动。

可选优化任务：

- 给多图表统计回复增加统一标题样式
- 在图表较多时支持折叠显示次要表格
- 当返回 `truncated=true` 时，在文本卡片或表格头部增加提示

说明：

- 若只追求功能上线，本轮可不改
- 若追求统计问答的可读性，可安排为第二优先级

---

### M. `backend/app/core/payload.py`

当前状态：现有 payload 已够用。

可选优化任务：

- 如果后续想做“分析总览卡片”再新增 payload 类型
- 本轮建议不改，先复用现有 `text/table/echarts_graph`

---

### N. `backend/app/api/routes_chat.py`

当前状态：聊天接口协议已满足本轮需求。

结论：

- 本轮不建议改

---

## 4.4 不建议本轮改动的文件

### O. `backend/app/skills/event_skills.py`

说明：

- 现有事件查询、详情、处置逻辑应尽量保持稳定
- 重点事件解读不要直接塞进本文件
- 建议单独新建分析 skill 文件，避免事件操作 skill 与统计 skill 耦合

唯一允许的轻量改动：

- 如果想抽 `_pick/_format_ts/_to_int` 等公共函数，可在保证风险可控的前提下整理到公共 util
- 若时间紧，不动此文件更稳妥

---

### P. `backend/app/skills/log_stats_skill.py`

说明：

- 当前实现是“总数 + 模拟趋势”，不适合继续叠加安全事件/告警趋势分析
- 本轮不建议把新需求压到这个文件里
- 新分析能力应单独建 skill 和 service

## 5. 推荐开发顺序

### 第一阶段：后端可跑通

1. 新建 `security_analytics_service.py`
2. 新建 `security_analytics_skills.py`
3. 修改 `registry.py`
4. 修改 `intent_parser.py`
5. 修改 `semantic_rules.py`

### 第二阶段：测试补齐

1. 新建 `test_security_analytics_service.py`
2. 新建 `test_security_analytics_skills.py`
3. 修改 `test_intent_parser.py`
4. 修改 `test_chat_confirm_flow.py`

### 第三阶段：文档与可读性优化

1. 修改 `docs/skill-api-matrix-spec.md`
2. 可选修改 `frontend/app.js`
3. 可选修改 `README.md`

## 6. 每个需求对应的主开发文件

### 需求 1：安全事件发生趋势

主文件：

- `backend/app/services/security_analytics_service.py`
- `backend/app/skills/security_analytics_skills.py`
- `backend/app/services/intent_parser.py`
- `backend/app/tests/test_security_analytics_service.py`
- `backend/app/tests/test_security_analytics_skills.py`

### 需求 2：安全事件类型分布

主文件：

- `backend/app/services/security_analytics_service.py`
- `backend/app/skills/security_analytics_skills.py`
- `backend/app/services/intent_parser.py`
- `backend/app/tests/test_security_analytics_service.py`
- `backend/app/tests/test_security_analytics_skills.py`

### 需求 3：安全事件处置成果

主文件：

- `backend/app/services/security_analytics_service.py`
- `backend/app/skills/security_analytics_skills.py`
- `backend/app/services/intent_parser.py`
- `backend/app/tests/test_security_analytics_service.py`
- `backend/app/tests/test_security_analytics_skills.py`

特别说明：

- 文案中必须明确“当前为状态快照版”

### 需求 4：重点安全事件解读

主文件：

- `backend/app/services/security_analytics_service.py`
- `backend/app/skills/security_analytics_skills.py`
- `backend/app/tests/test_security_analytics_skills.py`

特别说明：

- 需要串联事件列表、举证接口、实体接口

### 需求 5：安全告警分类情况

主文件：

- `backend/app/services/security_analytics_service.py`
- `backend/app/skills/security_analytics_skills.py`
- `backend/app/services/intent_parser.py`
- `backend/app/tests/test_security_analytics_service.py`
- `backend/app/tests/test_security_analytics_skills.py`
- `backend/app/tests/test_chat_confirm_flow.py`

## 7. 最小可交付版本定义

满足以下条件即可视为一期完成：

- 用户输入 5 类问题时可被正确识别
- 系统可以返回文本摘要
- 系统可以返回至少 1 个图表
- 系统可以返回至少 1 个明细表
- 重点事件解读能输出 Top3 事件简析
- 告警分类情况能输出一级/二级/三级分类 TopN
- 处置成果输出中带有限制说明

## 8. 建议的里程碑验收问句

开发完成后至少人工验证以下问句：

- 帮我统计最近 7 天的安全事件发生趋势
- 帮我看最近 24 小时高危和严重事件的发生趋势
- 最近 7 天安全事件类型分布
- 最近 7 天高危事件类型分布
- 最近 7 天安全事件处置成果
- 帮我解读最近 7 天最重要的 3 个安全事件
- 最近 7 天安全告警分类情况
- 最近 7 天高危告警分类情况

## 9. 风险提示

- 事件/告警接口分页上限会影响大时间窗口统计性能
- 分类名称字段若存在缺失，需要定义“未知分类”回退
- 重点事件解读涉及多次接口调用，需要限制默认 TopN，避免响应过慢
- 处置成果若未来要做“真实历史处置分析”，需要外部新增事件状态历史或处置流水接口
