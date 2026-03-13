# 一键深度研判（alert_triage）原型化改造清单（先评审后编码）

## 1. 需求理解确认

目标不是对当前 `Playbook 报告 · 单点告警深度研判` 做轻量美化，而是把它升级为你给出的原型样式：

1. 顶部是完整的研判页 Header，而不是普通报告卡标题。
2. 结论区必须“结论先行”，高危态势一眼可见。
3. 中部必须是三栏主信息面板：
   - 攻击源画像
   - 受害目标画像
   - 内部影响面
4. 底部必须是“攻击手法特征”区域，重点展示：
   - MITRE / 攻击手法标签
   - 关键恶意 Payload / 命令 / URL / 路径等证据片段
5. 顶部危险动作按钮要直接承接当前 Playbook 的处置链路，例如“一键封禁源 IP”。
6. 页面样式要尽量 100% 贴近原型，而不是继续沿用当前通用 report card 的布局。

结论：这次改造本质是“`alert_triage` 专属页面 + 后端结构化视图补齐”，不是单纯换 CSS。

---

## 2. 当前实现与差距（基于代码现状）

### 2.1 当前前端现状

当前 `alert_triage` 最终仍走通用报告卡渲染：

- `frontend/app.js` -> `renderPlaybookUnifiedCard`
- `frontend/app.js` -> `renderPlaybookResult`

当前行为：

1. 先显示统一标题 `Playbook 报告 · 单点告警深度研判`
2. 再按 payload 顺序展示：
   - 摘要
   - 任务目标事件表
   - 内部影响计数表
   - 外部情报表
   - 实体画像表
   - 下一步动作按钮

这与原型的差距很大：

1. 没有专属大盘式布局。
2. 没有顶部危险态势标识。
3. 没有三栏卡片化画像。
4. 没有攻击源 / 受害目标 / 影响面三段式信息架构。
5. 没有底部 MITRE + Payload 特征区。
6. 没有接近原型的沉浸式视觉层次。

### 2.2 当前后端现状

`backend/app/playbook/service.py` 中 `_build_alert_triage` 当前只输出：

1. LLM 文本摘要
2. `triage_targets` 表
3. `triage_impact` 表
4. `triage_intel` 表
5. `triage_entities` 表
6. `next_actions`

当前问题：

1. 后端没有产出专门给前端消费的 `triage_view` 结构。
2. 现有数据是“表格导向”，不适合直接做原型式布局。
3. 受害目标画像、攻击链证据、关键 payload、MITRE、资产价值等信息没有被系统化聚合输出。

结论：要想稳定实现原型，后端必须从“表格输出”升级为“结构化视图输出”。

---

## 3. 数据能力核对（你关心的新字段能否获取）

### 3.1 已有且可直接获取

#### 事件与结论

1. 事件 UUID
   - 来源：当前 `incident_uuid`
2. 研判结论文案
   - 来源：当前 `summary`
3. 下一步动作
   - 来源：当前 `next_actions`

#### 攻击源画像

1. 攻击源 IP
   - 来源：`GET /api/xdr/v1/incidents/{uuid}/entities/ip`
2. 国家 / 地域 / 位置
   - 来源：实体接口字段 `country / province / location`
3. 处置建议
   - 来源：实体接口字段 `dealSuggestion`
4. 外部情报等级 / 置信度 / 标签
   - 来源：ThreatBook 查询结果 + 当前 `_query_intel`
5. 额外威胁标签
   - 来源：实体接口字段 `intelligenceTag / mappingTag / alertRole`

#### 受害目标画像

1. 受害 IP
   - 来源：当前事件 / proof / impact 聚合后可推断
2. 主机名
   - 来源：`POST /api/xdr/v1/assets/list` 的 `hostName`
3. 资产价值
   - 来源：`POST /api/xdr/v1/assets/list` 的 `magnitude`
   - 文档枚举：`normal / core`
4. 资产辅助标签
   - 来源：`POST /api/xdr/v1/assets/list` 的 `tags / system / user / name / sourceDevice`

#### 影响面

1. 总访问量
   - 来源：当前 `node_4_internal_impact_count_parallel`
2. 高危访问量
   - 来源：当前 `node_4_internal_impact_count_parallel`
3. 成功 / 失陷量
   - 来源：当前 `node_4_internal_impact_count_parallel`

#### 攻击手法与证据

1. MITRE
   - 来源：`GET /api/xdr/v1/incidents/{uuid}/proof` 的 `mitreIds`
2. 漏洞信息
   - 来源：proof 的 `vulInfo / cve / vulType`
3. 关键命令 / Payload
   - 来源：proof 的 `cmdLine / path / url / domain / fileMd5`
4. AI 研判
   - 来源：proof 的 `gptResultDescription`
5. 风险标签
   - 来源：proof 的 `riskTag`

### 3.2 可以拿到，但需要做映射/推断

#### 资产角色

`获取资产` 接口没有一个标准化的 `role` 字段，但可以做稳定映射：

1. 优先使用资产名称 `name`
2. 结合 `tags`
3. 结合 `system`
4. 结合本地核心资产配置 `CoreAsset.asset_name / metadata_json`

建议策略：

1. 如果本地 `CoreAsset` 已配置自定义角色，优先使用本地配置。
2. 否则优先取资产 `name` 作为展示角色。
3. 若 `name` 为空，再退化为 `tags` 拼接后的摘要标签。
4. 再不行则退化为“普通服务器 / 终端 / 未命名资产”等通用文案。

#### 资产价值展示文案

接口里 `magnitude` 只有：

1. `core`
2. `normal`

所以前端展示建议映射成：

1. `core` -> `极高 (核心资产)`
2. `normal` -> `普通`

如果结合本地核心资产配置再增强，可以进一步展示为：

1. `core` + 命中核心资产清单 -> `极高 (Crown Jewel)`
2. `normal` -> `普通`

### 3.3 当前不能保证 100% 还原原型语义的字段

1. “近7天内有 14 次针对本行业的扫描记录”
   - 当前接口没有“行业维度”字段
   - 可以退化为“近7天命中 X 次相关扫描/攻击记录”
2. 原型里的完整 HTTP Raw Payload
   - 部分事件可以从 proof 拼到近似片段
   - 但不能保证每次都有完整 HTTP 请求报文

结论：你指出的 `主机名 / 资产角色 / 资产价值` 这块可以做，其中：

1. `主机名`：可以直接拿
2. `资产价值`：可以直接拿并映射
3. `资产角色`：可以通过资产接口字段 + 本地配置做稳定推断

---

## 4. 后端需要做的完整改动

主文件：`backend/app/playbook/service.py`

### 4.1 新增 alert_triage 专属结构化视图 `triage_view`

在 `_build_alert_triage` 的 finalizer 中，除保留当前 `cards` 外，新增：

1. `triage_view.header`
2. `triage_view.risk`
3. `triage_view.attacker`
4. `triage_view.victim`
5. `triage_view.impact`
6. `triage_view.tactics`
7. `triage_view.payload`
8. `triage_view.actions`
9. `triage_view.meta`

建议结构：

```json
{
  "triage_view": {
    "header": {
      "title": "Playbook 报告 · 单点告警深度研判",
      "incident_uuid": "incident-xxx",
      "severity": "严重",
      "severity_label": "紧急研判"
    },
    "risk": {
      "conclusion_title": "系统研判结论：攻击真实性极高",
      "conclusion_text": "......",
      "authenticity": "高",
      "authenticity_score": 92,
      "boundary_breached": true,
      "lateral_movement": true,
      "recommendation": "建议立即封禁"
    },
    "attacker": {
      "ip": "1.1.1.1",
      "location": "德国",
      "confidence": 98,
      "severity": "高危",
      "tags": ["C2", "僵尸网络"],
      "history_summary": "近7天命中14次相关攻击/扫描记录",
      "deal_suggestion": "建议封禁"
    },
    "victim": {
      "ip": "10.0.0.1",
      "host_name": "PRD-DB-01",
      "asset_name": "核心数据库",
      "asset_role": "核心用户数据库",
      "asset_value": "极高 (核心资产)",
      "system": "Linux",
      "tags": ["生产", "数据库"],
      "vulnerability": "CVE-2020-14882 / Weblogic RCE"
    },
    "impact": {
      "window_days": 7,
      "total_visits": 1250,
      "high_risk_visits": 45,
      "success_count": 3,
      "blast_radius_score": 99,
      "lateral_movement": true
    },
    "tactics": {
      "mitre": ["T1190", "T1059"],
      "risk_tags": ["Webshell", "RCE"],
      "ai_result": "......"
    },
    "payload": {
      "title": "提取的关键恶意 Payload 片段",
      "lines": ["cmd.exe ...", "curl ..."],
      "raw_text": "..."
    },
    "actions": {
      "danger_action": {},
      "next_actions": []
    },
    "meta": {
      "proof_errors": [],
      "entity_errors": [],
      "asset_errors": []
    }
  }
}
```

### 4.2 新增 proof 富化节点

在 `_build_alert_triage` 中新增一个 proof 聚合节点，例如：

1. `node_3_proof_enrich`

职责：

1. 调 `GET /api/xdr/v1/incidents/{uuid}/proof`
2. 提取：
   - `gptResultDescription`
   - `riskTag`
   - `mitreIds`
   - `vulInfo`
   - `cve`
   - `vulType`
   - `cmdLine`
   - `path`
   - `url`
   - `domain`
   - `fileMd5`
3. 生成：
   - `payload_lines`
   - `mitre_list`
   - `risk_tags`
   - `vulnerability_summary`
   - `proof_summary`

### 4.3 新增资产画像节点

新增例如：

1. `node_4_asset_profile`

职责：

1. 对受害 IP 调 `POST /api/xdr/v1/assets/list`
2. 取最匹配的一条资产记录
3. 提取：
   - `hostName`
   - `name`
   - `magnitude`
   - `system`
   - `tags`
   - `user`
   - `sourceDevice`
4. 如本地 `CoreAsset` 有同 IP 配置，合并：
   - `asset_name`
   - `metadata_json`

输出：

1. `host_name`
2. `asset_name`
3. `asset_role`
4. `asset_value`
5. `system`
6. `tags`

### 4.4 资产角色映射规则

在后端统一做，避免前端重复拼装。

建议规则：

1. 若本地 `CoreAsset.metadata_json.role` 存在，直接使用。
2. 否则若资产接口 `name` 非空，使用 `name`。
3. 否则若 `tags` 非空，取前 1-2 个标签组合。
4. 否则按 `system` 和 `magnitude` 退化：
   - `Linux/Windows + core` -> `核心服务器`
   - `Linux/Windows + normal` -> `服务器`
   - 其他 -> `普通资产`

### 4.5 资产价值映射规则

建议规则：

1. `magnitude == core`
   - 若本地核心资产存在 -> `极高 (Crown Jewel)`
   - 否则 -> `极高 (核心资产)`
2. `magnitude == normal`
   - -> `普通`
3. 为空
   - -> `未知`

### 4.6 横向移动信号补充

当前 `alert_triage` 只做 impact count，没有“是否发生横向移动”的结构化结论。

建议补一个轻量节点，例如：

1. `node_5_lateral_signal`

最小实现：

1. 复用 `threat_hunting` 中已存在的突破 / 横向分析思路
2. 若 proof/告警阶段中存在：
   - `内网扩散`
   - 管理端口高频命中
   - 多个内网目标命中
3. 则产出：
   - `lateral_movement: true`
   - `lateral_summary`

这样才能支撑原型里“监测到内部横向扩散”的结论标签。

### 4.7 保留现有 cards 作为兜底与导出

不要删除当前：

1. `triage_targets`
2. `triage_impact`
3. `triage_intel`
4. `triage_entities`

原因：

1. 兼容现有导出逻辑
2. 保留 debug / 审计可读性
3. 当前老渲染仍可兜底

---

## 5. 前端需要做的完整改动

主文件：`frontend/app.js`

### 5.1 为 alert_triage 新增专属渲染器

新增：

1. `buildAlertTriageViewModel(runData)`
2. `renderAlertTriageCard(runData)`

并在 `renderPlaybookResult` 中新增分支：

1. `if (runData?.template_id === 'alert_triage') renderAlertTriageCard(runData);`

不再让 `alert_triage` 落回通用 `renderPlaybookUnifiedCard`。

### 5.2 前端 ViewModel 层要做的映射

`buildAlertTriageViewModel` 需要：

1. 优先读 `result.triage_view`
2. 若后端还没返回 `triage_view`，则从旧 `cards/summary/next_actions` 兜底解析

需要整理的字段：

1. 页面标题
2. 事件 UUID
3. 紧急级别 badge
4. 结论标题 / 结论文案
5. 攻击源画像
6. 受害目标画像
7. 内部影响面
8. MITRE 标签
9. Payload 证据文本
10. 危险动作按钮
11. 弹窗执行态文案

### 5.3 页面结构要按原型拆为以下区域

#### 区域一：顶部 Header

包含：

1. 主标题
2. 紧急研判 badge
3. UUID
4. 右侧危险动作按钮

#### 区域二：结论先行区

包含：

1. 红色态势图标
2. 结论标题
3. 结论正文
4. 两个状态标签：
   - 攻击已穿透边界
   - 监测到内部横向扩散

#### 区域三：三栏主面板

1. 攻击源画像
   - IP
   - 地理位置
   - 情报置信度进度条
   - 威胁标签
   - 攻击历史摘要
2. 受害目标画像
   - 受害 IP
   - 主机名
   - 资产角色
   - 资产价值
   - 漏洞信息
3. 内部影响面
   - 近 7 天总访问量
   - 高危攻击量
   - 有效攻击次数

#### 区域四：攻击手法特征区

1. MITRE 标签
2. 风险标签
3. 关键 Payload / 命令 / URL / 路径证据块

#### 区域五：处置执行弹窗

点击危险动作后：

1. 展示执行中弹窗
2. 进度文本
3. 承接现有封禁流程或审批流程

### 5.4 危险动作的接入方式

优先复用当前 `next_actions` 中的 danger action。

行为规则：

1. 如果 danger action 是封禁 IP，则直接调现有处置链路。
2. 如果是审批型动作，则沿用现有 `runPlaybook` / `openRoutineBlockDialog` 逻辑。
3. Header 右上角只保留一个主危险动作按钮，避免和原型冲突。

---

## 6. 样式层需要做的完整改动

主文件：`frontend/styles.css`

### 6.1 新增 alert_triage 专属样式域

建议新增一组类名，例如：

1. `.alert-triage-card`
2. `.alert-triage-header`
3. `.alert-triage-badge`
4. `.alert-triage-danger-btn`
5. `.alert-triage-conclusion`
6. `.alert-triage-grid`
7. `.triage-panel`
8. `.triage-attacker-panel`
9. `.triage-victim-panel`
10. `.triage-impact-panel`
11. `.triage-mitre-chip`
12. `.triage-payload-block`
13. `.triage-block-modal`

### 6.2 外层工作区样式要做特例化

当前工作区是侧栏卡片容器，视觉会干扰原型。

建议在 alert_triage 页面打开时，对工作区做特例：

1. 减弱外层边框
2. 减小内边距干扰
3. 允许专属卡片撑满宽度
4. 适配移动端单列布局

### 6.3 样式目标

必须达到：

1. 深色背景
2. 红色高危结论强调
3. 三栏卡片明显分区
4. 字体层级和对比明显
5. Payload 区域具备终端感 / 证据感
6. 危险按钮视觉上与普通按钮区分明显

---

## 7. HTML 与工作区容器需要做的改动

主文件：`frontend/index.html`

当前结构：

1. Playbook Workspace 有固定标题栏
2. 内容区有默认空态

为了贴近原型，需要支持：

1. `alert_triage` 进入时用专属卡片完全占满工作区内容区
2. 必要时对 header 文案弱化，避免用户看到“双重标题”

这里不一定需要大改 DOM，但要支持通过 JS 给工作区挂专属 class，例如：

1. `playbook-workspace triage-mode`

---

## 8. 具体文件改动清单

### 8.1 后端

1. `backend/app/playbook/service.py`
   - 新增 `triage_view`
   - 新增 proof 富化节点
   - 新增资产画像节点
   - 新增 lateral signal 节点
   - 保留原有 `cards`

2. `backend/app/tests/test_playbook_service.py`
   - 补 `triage_view` 结构测试
   - 补资产字段映射测试
   - 补 proof dict/list 兼容测试
   - 补无资产命中降级测试

### 8.2 前端

1. `frontend/app.js`
   - 新增 `buildAlertTriageViewModel`
   - 新增 `renderAlertTriageCard`
   - 修改 `renderPlaybookResult`
   - 接入危险动作和执行态弹窗

2. `frontend/styles.css`
   - 新增 alert_triage 专属样式
   - 增加 triage-mode 工作区适配
   - 增加移动端样式

3. `frontend/index.html`
   - 如有需要，仅做最小结构配合

---

## 9. 测试与验证清单

### 9.1 后端验证

1. `triage_view.attacker.ip` 正常返回
2. `triage_view.victim.host_name` 可从资产接口拿到
3. `triage_view.victim.asset_value` 能根据 `magnitude` 正确映射
4. `triage_view.victim.asset_role` 能根据 `CoreAsset/name/tags/system` 正确退化
5. `triage_view.tactics.mitre` 能从 proof 拿到
6. `triage_view.payload.raw_text` 至少能输出一个证据片段
7. `triage_view.risk.lateral_movement` 在可识别场景下能正确返回

### 9.2 前端验证

1. `alert_triage` 不再走通用 report card
2. 页面结构与原型一致
3. 三栏在桌面端正常展示
4. 移动端自动降为单列
5. 危险按钮点击后能进入现有处置链路
6. 没有资产信息时页面仍可展示降级文案
7. 没有 MITRE / payload 时不会出现空白断层

---

## 10. 风险点与降级策略

### 10.1 资产角色不是标准字段

风险：

1. 资产接口没有直接 `role`

策略：

1. 后端统一做映射
2. 优先本地核心资产 metadata
3. 其次资产 `name`
4. 再次 `tags`
5. 最后通用文案降级

### 10.2 proof 不一定总有完整 payload

风险：

1. 有些事件只有部分 `cmdLine/path/domain/fileMd5`

策略：

1. 允许优先显示最强证据片段
2. 无完整原始载荷时，用拼接后的证据摘要替代

### 10.3 “攻击历史”不能完全照搬原型语义

风险：

1. 当前无法得到“针对本行业”的精确历史统计

策略：

1. 改为“近7天命中 X 次相关攻击/扫描记录”
2. 若后续有行业维度接口，再升级文案

---

## 11. 验收标准

本次改造完成后，应满足：

1. `alert_triage` 页面视觉结构与原型高度一致。
2. 一进入结果页，首先看到的是“高危研判结论”，不是表格。
3. 页面必须具备三栏画像信息架构。
4. 主机名、资产角色、资产价值必须展示出来。
5. 主机名和资产价值必须来自 `获取资产` 接口。
6. 资产角色必须通过资产接口字段与本地资产配置做稳定映射。
7. MITRE 与 Payload 特征区必须可展示。
8. 危险动作按钮必须能承接现有封禁/审批链路。
9. 保留原有 `cards`，避免导出和兼容性回退失效。

---

## 12. 实施建议顺序

建议按以下顺序落地：

1. 后端补 `triage_view` 结构
2. 后端补资产画像与 proof 富化
3. 前端完成 `alert_triage` 专属 ViewModel
4. 前端完成专属页面渲染
5. 前端补危险动作执行态弹窗
6. 最后做样式细修与移动端适配

这样可以保证：

1. 数据层先稳定
2. 页面不会反复推翻
3. 原型还原效率更高
