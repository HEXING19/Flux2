# threat_hunting 行为阶段详细分析改造清单（先评审后编码）

## 1. 需求理解确认

目标是把当前 `threat_hunting` 的“行为阶段详细分析”从“基于告警时间线的静态分段展示”，升级为“按真实人工溯源流程的 Pivot 推演”：

1. 阶段一：外部攻击源线索锁定与攻击面探明（外部 -> 边界）。
2. 阶段二：突破口确认后，切换视角到 Victim A，跟踪横向移动（边界 -> 内网）。
3. 阶段三：从失陷主机出站行为中识别异常外联行为（内网 -> 外部）。
4. 阶段四：输出完整 Kill Chain 闭环（T0/T1/T2/T3/T4）。

你指出的核心问题是：**当前“行为阶段详细分析”的数据采集没有按 Pivot 逐跳推进**，导致阶段结论偏“模板化”而非“证据驱动”。

---

## 2. 当前实现与差距（基于代码现状）

当前实现位置：

- `backend/app/playbook/service.py` 中 `_build_threat_hunting`
- 前端渲染在 `frontend/app.js`（`buildThreatHuntingViewModel` + `renderThreatHuntingCard`）

当前流程（简化）：

1. 拉目标 IP 外部情报。
2. 按目标 IP（src/dst）拉告警清单。
3. 对告警关联对象并发拉 `proof/entities`。
4. 按 7/30/90 天做 `count`。
5. LLM 输出“侦察->利用->横向->结果”叙事。

差距：

1. 没有明确“突破口确认 -> Victim A 视角切换”。
2. 没有基于 Victim A 的“管理端口横向移动”专项检测。
3. 阶段三“失陷主机出站行为”尚未形成独立结构化证据，更多依赖泛化叙事。
4. Kill Chain 时间点不是严格由阶段证据反推得到。

---

## 3. 接口能力核对（是否具备）

### 3.1 已具备且可直接用

1. `POST /api/xdr/v1/alerts/list`
   - 请求可按 `srcIps/dstIps/severities/accessDirections` 等过滤。
   - 返回含 `stage/attackState/srcIp/srcPort/dstIp/dstPort/url/domain/fileMd5/lastTime` 等字段，可用于：
     - 攻击面 Group by（dest_ip, dest_port）
     - 突破口候选筛选（高危、成功/失陷）
     - 横向端口检测（445/139/3389/22/5985）
     - 外联对象聚合（用于阶段三出站行为分析）
2. `POST /api/xdr/v1/incidents/list`
   - 事件集合检索与分页，可做 incident 维度补充。
3. `GET /api/xdr/v1/incidents/{uuid}/proof`
   - 可拿 `incidentTimeLines/alertTimeLine/proof`，并包含 `cmdLine/path/srcIps/dstIps/attackResult` 等，适合做突破口证据提取。
4. `GET /api/xdr/v1/incidents/{uuid}/entities/ip`
   - 可拿外网实体、标签、角色（如 `alertRole`）等，适合补充节点画像。
5. `POST /api/xdr/v1/analysislog/networksecurity/count`
   - 可做窗口统计（本次方案统一30天）。

### 3.2 接口层面的实现方式说明

1. 当前仓库 API 文档没有“服务端 `GROUP BY dest_ip,dest_port`”统计接口。
   - 处理：通过 `alerts/list` 分页拉取后本地聚合实现。
2. 本次需求不依赖网络流量明细（字节/包长/会话持续时长）。
   - 处理：阶段三直接基于告警维度的出站连接证据完成判定与展示。

结论：**按你的流程做“证据驱动版阶段分析”可直接实现，不需要新增流量明细接口。**

---

## 4. 后端详细改造（可编码级）

改造主文件：`backend/app/playbook/service.py`

### 4.1 threat_hunting DAG 重构

将当前 5 个节点重构为以下语义（节点名也同步调整）：

1. `node_1_attack_surface_recon`
   - 输入：`target_ip`, 时间窗（统一固定30天）
   - 动作：
     - 优先按“外部攻击源”口径拉取：`alerts/list` 使用 `srcIps=[target_ip]`
     - 若 `srcIps` 命中不足（如总量过低或无法支持攻击面判定），再兜底补拉 `dstIps=[target_ip]`
     - 本地 Group by `dest_ip,dest_port`
     - 计算首次活跃、最近活跃、活动频次、严重等级分布
   - 产出：
     - `phase1_surface_metrics`
     - `candidate_victims`（潜在受害主机候选）
     - `attack_intent`（无差别扫描/定向打击）

2. `node_2_breakthrough_identify`
   - 输入：阶段一候选 + 命中告警
   - 动作：
     - 选取“最后一条高置信突破告警”候选（优先 `attackState in [2,3]` + 高危 + 与候选 Victim 关联）
     - 拉 `proof` + `entities/ip`
     - 提取 payload 证据：`url/path/cmdLine/fileMd5/threatSubTypeDesc`
   - 产出：
     - `victim_a_ip`
     - `breakthrough_time`
     - `breakthrough_evidence`

3. `node_3_victim_lateral_movement`
   - 输入：`victim_a_ip`, `breakthrough_time`
   - 动作：
     - 查询 `srcIps=[victim_a_ip]` 且时间范围 `breakthrough_time -> now`
     - 过滤 `dst` 为内网（RFC1918 + 安全防线自定义网段）
     - 仅排除 `dst == victim_a_ip` 的自环记录（避免把本机回环/自连噪声计入横向）
     - 端口策略采用“重点端口 + 自适应异常端口”：
       - 重点端口：`445,139,3389,22,5985,5986,135`
       - 自适应异常端口：在同窗口内按频次提取 TopN 新增可疑端口（不在重点端口集合中）
     - 统计横向广度（目标主机数、端口分布、连接频度）
   - 产出：
     - `lateral_confirmed`
     - `victim_b_candidates`
     - `lateral_evidence`

4. `node_4_outbound_behavior_analysis`
   - 输入：`[victim_a + victim_b_candidates]`
   - 动作：
     - 对每个失陷主机查询出站告警（内网源 -> 外网目的）
     - 聚合外联目标、端口、阶段、严重性、最近活跃时间
     - 形成“失陷主机出站行为”证据，不做 C2/Beacon 强制判定
   - 产出：
     - `outbound_targets`
     - `outbound_behavior_evidence`

5. `node_5_kill_chain_finalize`
   - 输入：前四阶段结构化证据
   - 动作：
     - 构造 T0~T4 时间点
     - 产出可解释的 `kill_chain_stages` 与 `stage_evidence_cards`
     - LLM 只做润色，不再主导事实归因
   - 产出：
     - `threat_view`（保持前端兼容字段 + 新增 phase 结构）

### 4.2 新增/增强的内部工具函数

建议新增函数（同文件）：

1. `_normalize_alert_row_v2`：补齐 `stage/attackState/srcPort/dstPort/url/domain/fileMd5` 标准化。
2. `_explode_alert_endpoints(alert_row)`：把数组型 `srcIp/dstIp/dstPort` 展开为可聚合连接元组。
3. `_group_surface_by_dst(alert_rows)`：输出 `dest_ip,dest_port,hits,last_seen`。
4. `_infer_attack_intent(grouped_rows)`：无差别扫描 vs 定向攻击规则判定。
5. `_pick_breakthrough_alert(...)`：基于严重性+攻击状态+时间排序选突破口告警。
6. `_extract_breakthrough_payload(proof_data)`：提取 `url/path/cmdLine/fileMd5` 等证据。
7. `_detect_lateral_movement(alert_rows, victim_a_ip)`：管理端口横向检测。
8. `_is_internal_ip_with_safety_gate(ip)`：内网判定（RFC1918 + 安全防线自定义 `cidr/ip`）。
9. `_analyze_outbound_behavior(alert_rows, compromised_hosts)`：出站行为聚合（目标、端口、阶段、严重性、最近活跃）。

### 4.3 threat_view 数据结构调整（兼容前端）

保留已有字段：

- `kill_chain_stages`
- `stage_evidence_cards`
- `alert_table_rows`
- `risk`

新增字段：

1. `phase_1_surface`
2. `phase_2_breakthrough`
3. `phase_3_lateral`
4. `phase_4_outbound`
5. `pivot_nodes`（`attacker_ip/victim_a/victim_b[]/outbound_targets[]`）
6. `timeline_points`（`T0..T4`）

说明：前端先复用现有字段可不阻塞；新增字段用于下一步增强展示。

### 4.4 参数与输入规范补充

在 `_normalize_params("threat_hunting", ...)` 调整为：

1. `window_days` 固定写死为 `30`（忽略外部传入的 90 或其他值）。
2. `pivot_ports` 默认`[445,139,3389,22,5985,5986,135]`（可保留可配）。
3. `adaptive_port_topn` 默认 `5`（自适应异常端口数量上限，可配）。
4. `src_only_first` 默认 `true`（阶段一先查 `srcIps`，不足时再补 `dstIps`）。

---

## 5. 前端改造清单（最小必要）

主文件：`frontend/app.js`

1. `PLAYBOOK_STAGE_META.threat_hunting` 改为新节点文案，确保运行进度可读。
2. `buildThreatHuntingViewModel`：
   - 优先读取后端结构化阶段结论，不再依赖故事文本反解析。
   - 若后端未返回新字段，保留旧兜底逻辑。
3. `renderThreatHuntingCard`：
   - “行为阶段详细分析”卡片可追加展示：
     - Pivot 主机（Victim A/B）
     - 关键端口证据
     - 外联目标

---

## 6. 测试改造清单（必须补）

主文件：`backend/app/tests/test_playbook_service.py`

新增/修改测试点：

1. 阶段一：能输出 `attack_intent` 与目标面聚合。
2. 阶段二：能稳定选出 `victim_a_ip` 与 `breakthrough_time`。
3. 阶段三：当出现 445/3389 等端口时 `lateral_confirmed=True`。
4. 阶段三：当重点端口不足时，仍可通过“异常高频端口 TopN”补充横向可疑证据。
5. 阶段四：能输出失陷主机出站行为聚合（`outbound_targets` 与最近活跃证据）。
6. 兼容性：`threat_view.kill_chain_stages/stage_evidence_cards/alert_table_rows` 仍存在。
7. 降级：当 `proof/entities` 部分失败时，仍返回可用报告与错误提示。

---

## 7. 验收标准（达到“可编码完成”）

1. 阶段分析必须由结构化证据驱动，LLM 仅做摘要。
2. 能明确给出 Victim A（如存在）并在阶段二/三中作为 Pivot。
3. 阶段三必须输出“重点端口 + 自适应异常端口”的横向证据（命中数、目标、时间）。
4. 阶段四必须输出失陷主机出站行为证据（外联目标、端口、阶段、时间）。
5. 前端“行为阶段详细分析”展示的数据与后端阶段证据一致。

---

## 8. 已确认约束（按你的反馈固化）

1. 内网判定口径：`RFC1918 私网 + 高危指令硬拦截防线模块（Safety Gate）中的自定义 ip/cidr`。
2. 扫描 vs 定向阈值：采用文档默认阈值（可后续微调）。
3. 不做 Beacon 阈值判定：阶段三聚焦“失陷主机出站行为识别”本身。
4. 前端阶段命名保持：`侦察 / 利用 / 横向 / 结果`。
5. 时间窗口统一：`30天`（所有阶段同口径）。
6. 突破口选择对象：从“告警”中选取最后一条高置信突破告警，不从事件集合直接选。
7. 阶段一查询策略：输入明确为外部攻击源 IP，先查 `srcIps`，命中不足再补 `dstIps`。
8. 阶段三端口策略：采用“重点端口 + 自适应异常端口”。
9. 关于“为什么排除 dst”：
   - 仅排除 `dst == victim_a_ip` 的自环记录，不排除其他内网 `dst`。
   - 目的：避免把主机自连接/回环噪声误计入横向扩散证据。

---

## 9. 实施顺序（建议）

1. 先改后端 DAG 与结构化数据输出（不改 UI）。
2. 再改前端映射与展示。
3. 最后补全单测并回归现有场景（routine_check/alert_triage/asset_guard）。
