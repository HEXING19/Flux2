# 核心资产防线透视样式改造清单（评审后进入编码）

## 1. 需求理解确认

本次目标是：

1. 以前端原型文件 `核心资产防线透视.jsx` 为准，落地到现有项目；
2. 要求达到“像素级还原”；
3. 先输出改动点到 `action3.md`，你确认后再进入编码；
4. 同时核验是否需要新增数据获取。

## 2. 现状与差距（已核对）

当前前端对 `asset_guard` 没有专用卡片渲染，仍走通用 `renderPlaybookUnifiedCard`，所以版式和原型差距较大（结构、层级、色彩、交互都不一致）。

已核对代码位置：

1. 前端入口：`frontend/app.js`  
   `renderPlaybookResult` 仅对 `routine_check / alert_triage / threat_hunting` 做专用渲染，`asset_guard` 走默认通用渲染。
2. 后端结果：`backend/app/playbook/service.py` `_build_asset_guard().finalizer`  
   已输出 `summary + cards + next_actions + asset`，数据类别完整。

## 3. 数据核验结论（是否要新增数据获取）

结论：**不需要新增外部接口请求**，现有数据可覆盖原型展示主体。

原型字段与当前结果映射如下：

1. 核心资产 IP、评估周期  
   - 来自 `result.asset.asset_ip / result.asset.window_hours`
2. 入向/出向告警与访问量  
   - 来自 `cards` 中 `namespace=asset_guard_stats` 的两行数据
3. Top 5 外部访问实体（IP、威胁等级、置信度、标签、来源）  
   - 来自 `namespace=asset_guard_intel`
4. AI 透视结论  
   - 来自图表卡 `echarts_graph.data.summary`
5. 建议响应动作文案  
   - 来自“建议动作”文本卡
6. 批量封禁目标 IP  
   - 来自 `next_actions[*].params.ips`（危险动作）

注意项（像素级还原相关）：

1. 原型中的“近7天双向柱（入向+出向分离）”是双序列视觉。  
2. 当前后端图表 `option` 默认只返回合并后的单序列（虽然服务端计算过程中已有 `src_high/dst_high`）。  
3. 要 100% 贴近原型双柱效果，建议在后端结果中补充“入向/出向日维度数组”字段；这不需要新增任何外部接口，只是把已计算数据透出。

## 4. 拟改动点（进入编码时执行）

### 4.1 `frontend/app.js`

1. 新增 `buildAssetGuardViewModel(runData)`：
   - 从 `result.asset`、`cards(namespace)`、`next_actions` 解析并归一化页面所需数据；
   - 处理空数据兜底；
   - 解析置信度百分比为数值，供进度条使用；
   - 统一 severity/tag/source 的展示文案与样式类型。
2. 新增 `renderAssetGuardCard(runData)`：
   - 按原型结构渲染 6 大区块：Header、3 个指标卡、图表与 AI 结论、双向统计表、Top5 情报表、建议动作中心；
   - 动作中心实现“IP Chip 可移除 + 按剩余数量更新按钮文案”；
   - 危险动作按钮复用现有 `openRoutineBlockDialog(...)` 流程，不改变后端动作协议；
   - 支持无 `next_actions` 时的降级展示。
3. `renderPlaybookResult(runData)` 增加 `asset_guard` 分支，切换到专用渲染，不再走 generic。

### 4.2 `frontend/styles.css`

1. 新增 `asset_guard` 专属样式命名空间（避免影响现有场景）：
   - 卡片容器、标题区、副标题、指标卡、彩色侧边条；
   - 图表容器、AI 结论框、表格、等级徽章、置信度条；
   - 动作中心、IP Chip、主按钮禁用/可用态。
2. 对齐原型视觉参数：
   - 间距、圆角、边框透明度、阴影、字重与字号层级；
   - 暗色背景分层与 hover 态；
   - 顶部/表格/动作区的栅格比例。
3. 响应式：
   - `>=1024` 双列布局；
   - `<1024` 收敛为单列；
   - `<768` 压缩间距与字体，保证可读性。

### 4.3 `backend/app/playbook/service.py`（仅当你同意）

1. 在 `asset_guard finalizer` 里额外返回 `asset_guard_view.trend`（`labels/inbound/outbound`）；
2. 不改现有 `cards` 协议，保持向后兼容；
3. 不新增外部 API 调用。

## 5. 验收标准（编码后对齐）

1. 页面结构与原型一致：6 大区块完整，顺序一致；
2. 配色、间距、字号、边框、hover 与原型一致；
3. 数据语义不变：仍使用当前 Playbook 结果，不引入新接口依赖；
4. “批量封禁审批”交互可用：可移除目标、可提交审批；
5. 不影响其他三类场景（`routine_check/alert_triage/threat_hunting`）。

