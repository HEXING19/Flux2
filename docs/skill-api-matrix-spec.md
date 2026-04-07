# Flux Skill-API Matrix Specification

## 1. Scope

This document defines the enterprise implementation baseline for:

- Natural language request patterns (Chinese first)
- Intent/slot mapping (Flux IR input layer)
- Skill-to-XDR API contract mapping
- Missing-parameter ask-back rules
- Confirmation and safety gating rules
- Delivery boundaries for phase-1 and phase-2

Referenced API docs are under `docs/api-ref/`.

## 2. Skill-API Matrix

| Skill | Intent | API | Required Fields | Output |
| --- | --- | --- | --- | --- |
| EventQuerySkill | `event_query` | `POST /api/xdr/v1/incidents/list` | none (time range defaults supported by API) | text summary + table + `events` index mapping |
| AlertQuerySkill | `alert_query` | `POST /api/xdr/v1/alerts/list` | none (time range defaults supported by API) | text summary + table + `alerts` index mapping |
| EventDetailSkill | `event_detail` | `GET /api/xdr/v1/incidents/{uuid}/proof` | `uuids` (direct or resolved from index) | text detail + timeline table |
| EntityQuerySkill | `entity_query` | `GET /api/xdr/v1/incidents/{uuid}/entities/ip` | `uuid` or resolvable event reference | text summary + entity table |
| EventActionSkill | `event_action` | `POST /api/xdr/v1/incidents/dealstatus` | `uuids`, `deal_status` | dangerous text result |
| EventTrendSkill | `event_trend` | `POST /api/xdr/v1/incidents/list` | none (defaults to recent 7 days when omitted) | text summary + 2 charts + trend table |
| AlertTrendSkill | `alert_trend` | `POST /api/xdr/v1/alerts/list` | none (defaults to recent 7 days when omitted) | text summary + 2 charts + trend table |
| EventTypeDistributionSkill | `event_type_distribution` | `POST /api/xdr/v1/incidents/list` | none (defaults to recent 7 days when omitted) | text summary + 3 charts + distribution table |
| EventDispositionSummarySkill | `event_disposition_summary` | `POST /api/xdr/v1/incidents/list` | none (defaults to recent 7 days when omitted) | text summary + 2 charts + 2 tables |
| KeyEventInsightSkill | `key_event_insight` | `POST /api/xdr/v1/incidents/list` + `GET /api/xdr/v1/incidents/{uuid}/proof` + `GET /api/xdr/v1/incidents/{uuid}/entities/ip` | none (defaults to recent 7 days when omitted) | text summary + key-event table + per-event insight text/table |
| AlertClassificationSummarySkill | `alert_classification_summary` | `POST /api/xdr/v1/alerts/list` | none (defaults to recent 7 days when omitted) | text summary + multi-chart classification view + table |
| BlockQuerySkill | `block_query` | `POST /api/xdr/v1/responses/blockiprule/list` | `page`, `page_size` | text summary + block-rule table + `block_rules` index mapping |
| BlockActionSkill | `block_action` | `POST /api/xdr/v1/device/blockdevice/list` + `POST /api/xdr/v1/responses/blockiprule/network` | `block_type`, `views`, `time_type`, `devices` (and temporary duration fields) | dangerous text result |
| LogStatsSkill | `log_stats` | `POST /api/xdr/v1/analysislog/networksecurity/count` | none | chart payload (`echarts_graph`) |

## 3. NL Intent and Slot Mapping

### 3.1 Event Query

- Examples:
  - `查询最近7天高危事件`
  - `最近三天前20条事件`
- Slots:
  - `time_text`, `severities`, `deal_status`, `page_size`

### 3.2 Alert Query

- Examples:
  - `查看24小时的告警信息`
  - `查询最近7天高危告警`
- Slots:
  - `time_text`, `severities`, `page_size`

### 3.3 Event Detail

- Examples:
  - `查看第3个事件详情`
  - `刚刚那个事件的举证`
- Slots:
  - `ref_text` -> resolve to `uuids`

### 3.4 Event Action

- Examples:
  - `把前两个标记为已处置`
  - `第1个和第3个改成处置中，备注人工复核`
- Slots:
  - `ref_text`, `deal_status`, `deal_comment`

### 3.5 Block Query

- Examples:
  - `查1.2.3.4是否被封禁`
  - `查询包含example.com的封禁策略`
- Slots:
  - `keyword`, `status`, `time_text`

### 3.6 Block Action

- Examples:
  - `封禁源IP 1.2.3.4 24小时`
  - `永久封禁域名 bad.com`
- Slots:
  - `block_type`, `views`, `time_type`, `time_value`, `time_unit`, `devices`, `reason`, `name`

### 3.7 Entity Query

- Examples:
  - `查询第1个事件外网实体`
  - `查看 incident-xxx 的外网IP`
- Slots:
  - `ref_text` or `ips`

### 3.8 Log Stats

- Examples:
  - `统计最近30天网络安全日志总数`
  - `查询高危日志总数并画趋势`
- Slots:
  - `time_text`, `severities`, `product_types`

### 3.9 Event Trend

- Examples:
  - `帮我统计最近7天的安全事件发生趋势`
  - `最近24小时安全事件趋势`
- Slots:
  - `time_text`, `severities`, optional `group_by`
- Notes:
  - Default aggregation is by day; automatically switches to hourly when the window is within 48 hours.

### 3.10 Alert Trend

- Examples:
  - `总结最近7天的告警趋势`
  - `帮我总结一下最近7天的安全告警发生趋势`
- Slots:
  - `time_text`, `severities`, optional `group_by`
- Notes:
  - Default aggregation is by day; automatically switches to hourly when the window is within 48 hours.

### 3.11 Event Type Distribution

- Examples:
  - `最近7天安全事件类型分布`
  - `最近7天高危事件威胁类型分布 Top5`
- Slots:
  - `time_text`, `severities`, optional `top_n`
- Missing params:
  - When omitted, defaults to recent 7 days and built-in TopN.

### 3.12 Event Disposition Summary

- Examples:
  - `最近7天安全事件处置成果`
  - `最近三天高危事件处置统计`
- Slots:
  - `time_text`, `severities`, optional `top_n`
- Delivery limit:
  - Current version is a snapshot of current `dealStatus` / `dealAction`.
  - Historical completion trend, average handling time, and status transition history are not available from current APIs.

### 3.13 Key Event Insight

- Examples:
  - `重点安全事件解读`
  - `帮我解读重点事件 Top3`
- Slots:
  - `time_text`, `severities`, optional `page_size`, optional `top_n`
- Notes:
  - Default ranking is `severity desc -> unresolved first -> latest event time desc`.

### 3.14 Alert Classification Summary

- Examples:
  - `最近7天安全告警分类情况`
  - `最近24小时告警三级分类分布`
- Slots:
  - `time_text`, `severities`, optional `top_n`
- Missing params:
  - When omitted, defaults to recent 7 days and returns TopN for class/type/subtype.

## 4. Ask-Back Rules for Missing Parameters

### 4.1 EventActionSkill

- Missing target:
  - `请指定要处置的事件序号，例如“把前两个标记为已处置”。`
- Missing status:
  - `请说明目标状态，例如“处置中”或“已处置”。`

### 4.2 BlockActionSkill

- Missing block type:
  - `请确认封禁对象类型：源IP、目的IP、域名或URL。`
- Missing view:
  - `请提供要封禁的对象，例如“1.2.3.4”或“example.com”。`
- Missing device in multi-device case:
  - `检测到多个在线设备，请先选择目标设备。`
- Missing temporary duration:
  - `临时封禁请补充时长与单位，例如“2小时”或“1天”。`

## 5. Confirmation and Safety Policy

### 5.1 Mandatory Confirmation

- `event_action`: always requires confirmation
- `block_action`: always requires confirmation

### 5.2 Safety Gate Policy

- Block dangerous targets:
  - Built-in dangerous IP/domain/cidr list
  - User custom safety rules
- Reject execution if policy violated

## 6. Enterprise Delivery Baseline

### 6.1 Must-have (Current Phase)

- Stable pipeline layering: `Intent -> IR -> Lint -> Safety -> Execute -> Render`
- Persistent session state for:
  - parameter memory
  - index mapping
  - pending confirmation/form state
- Audit trail persistence for dangerous actions and workflow decisions
- Docker one-command deployment

### 6.2 Deferred (Next Phase)

- Unblock/rollback API action (pending API contract)
- Distributed lock and queue-backed scheduler
- Centralized metrics and tracing export
